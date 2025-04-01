mod noise;
pub mod qtls;
pub mod transporter;

use core::str;
use std::{
    future,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
};

use bytes::Buf;
use h3::client::SendRequest;

use crate::{
    chttp::genrequrl,
    config::{self, Noise},
    rule::rulecheck,
    utils::{Buffering, unsafe_staticref},
};

pub async fn client_noise(addr: SocketAddr, target: SocketAddr, noise: Noise) -> quinn::Endpoint {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    socket.bind(&addr.into()).unwrap();

    // send noises
    if noise.enable {
        noise::noiser(noise, target, &socket).await;
    }

    let runtime = quinn::default_runtime()
        .ok_or_else(|| tokio::io::Error::new(tokio::io::ErrorKind::Other, "no async runtime found"))
        .unwrap();
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        runtime.wrap_udp_socket(socket.into()).unwrap(),
        runtime,
    )
    .unwrap()
}

pub async fn udp_setup(
    target: SocketAddr,
    noise: Noise,
    quic_conf_file: crate::config::Quic,
    alpn: &str,
    network_interface: &'static Option<String>,
) -> quinn::Endpoint {
    let quic_udp_binding_addr = {
        if let Some(interface) = network_interface {
            crate::interface::get_interface(target.is_ipv4(), interface.as_str())
        } else if target.is_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        }
    };

    let mut endpoint = client_noise(quic_udp_binding_addr, target, noise).await;

    endpoint.set_default_client_config(
        quinn::ClientConfig::new(qtls::qtls(alpn))
            .transport_config(transporter::tc(quic_conf_file))
            .to_owned(),
    );

    endpoint
}

pub async fn http3(
    sn: &'static str,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    quic_conf_file: config::Quic,
    noise: Noise,
    connection: config::Connection,
    rules: &Option<Vec<crate::rule::Rule>>,
    ucpath: &'static Option<String>,
    network_interface: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
    hm: config::HttpMethod,
) {
    let mut endpoint = udp_setup(
        socket_addrs,
        noise.clone(),
        quic_conf_file.clone(),
        "h3",
        network_interface,
    )
    .await;

    let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let mut retry = 0u8;
    loop {
        if retry == connection.max_reconnect {
            println!(
                "Max retry reached. Sleeping for {}",
                connection.max_reconnect_sleep
            );
            sleep(std::time::Duration::from_secs(
                connection.max_reconnect_sleep,
            ))
            .await;
            retry = 0;
            // on windows when pc goes sleep the endpoint config is fucked up
            endpoint = udp_setup(
                socket_addrs,
                noise.clone(),
                quic_conf_file.clone(),
                "h3",
                network_interface,
            )
            .await;
            continue;
        }

        println!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint.connect(socket_addrs, sn).unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(quic_conf_file.connecting_timeout_sec),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        println!("QUIC 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint.connect(socket_addrs, sn).unwrap().await;
                        if conn.is_ok() {
                            println!("QUIC Connection Established");
                        }
                        conn
                    }
                },
            )
            .await;

            if let Ok(pending) = timing {
                pending
            } else {
                println!("Connecting timeout");
                retry += 1;
                continue;
            }
        };

        if conn.is_err() {
            println!("{}", conn.unwrap_err());
            retry += 1;
            sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
            continue;
        }

        // QUIC Connection Established
        retry = 0;

        let dead_conn = Arc::new(Mutex::new(false));

        // HTTP/3 Client
        let (mut driver, h3) = h3::client::new(h3_quinn::Connection::new(conn.unwrap()))
            .await
            .unwrap();
        let deriver_dead_conn = dead_conn.clone();
        let drive = async move {
            future::poll_fn(|cx| driver.poll_close(cx)).await?;
            *(deriver_dead_conn.lock().await) = true;
            Ok::<(), h3::Error>(())
        };

        tokio::spawn(drive);

        let mut dns_query = [0u8; 512];
        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let quic_conn_dead = dead_conn.clone();

            if let Some((dns_query, query_size, addr)) = tank {
                let h3 = h3.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) =
                        send_request(sn, h3, (*dns_query, query_size), addr, uudp, ucpath, ow, hm)
                            .await
                    {
                        println!("{e}");
                        temp = true;
                    }
                    if temp {
                        *(quic_conn_dead.lock().await) = true;
                    }
                });

                tank = None;
                continue;
            }

            // Recive dns query
            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
                // rule check
                if (rules.is_some()
                    && rulecheck(
                        rules,
                        crate::rule::RuleDqt::Http(dns_query, query_size),
                        addr,
                        uudp,
                    )
                    .await)
                    || query_size < 12
                {
                    continue;
                }

                if *quic_conn_dead.lock().await {
                    tank = Some((Box::new(dns_query), query_size, addr));
                    break;
                }

                let h3 = h3.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) =
                        send_request(sn, h3, (dns_query, query_size), addr, uudp, ucpath, ow, hm)
                            .await
                    {
                        println!("{e}");
                        temp = true;
                    }
                    if temp {
                        *(quic_conn_dead.lock().await) = true;
                    }
                });
            }
        }
    }
}

async fn send_request(
    server_name: &'static str,
    mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    dns_query: ([u8; 512], usize),
    addr: SocketAddr,
    udp: &'static tokio::net::UdpSocket,
    cpath: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
    hm: config::HttpMethod,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reqs = match hm {
        config::HttpMethod::GET => {
            let mut temp = [0u8; 512];
            let mut url = [0; 1024];
            h3.send_request(
                http::Request::get(genrequrl(
                    &mut Buffering(&mut url, 0),
                    server_name.as_bytes(),
                    base64_url::encode_to_slice(&dns_query.0[..dns_query.1], &mut temp)?,
                    cpath,
                )?)
                .version(http::Version::HTTP_3)
                .header("Accept", "application/dns-message")
                .body(())?,
            )
            .await?
        }
        config::HttpMethod::POST => {
            let p = if let Some(path) = cpath {
                path.as_str()
            } else {
                "/dns-query"
            };
            let mut pending = h3
                .send_request(
                    http::Request::post(
                        http::Uri::builder()
                            .scheme("https")
                            .authority(server_name)
                            .path_and_query(p)
                            .build()?,
                    )
                    .header("Accept", "application/dns-message")
                    .header("Content-Type", "application/dns-message")
                    .header("content-length", dns_query.1)
                    .version(http::Version::HTTP_3)
                    .body(())?,
                )
                .await?;
            // pending
            pending
                .send_data(bytes::Bytes::copy_from_slice(&dns_query.0[..dns_query.1]))
                .await?;
            pending
        }
    };

    reqs.finish().await?;

    if reqs.recv_response().await?.status() == http::status::StatusCode::OK {
        // get body
        if let Some(body) = reqs.recv_data().await? {
            let mut buff = [0; 4096];
            let body_len = body.reader().read(&mut buff)?;
            if ow.is_some() {
                crate::ipoverwrite::overwrite_ip(&mut buff[..body_len], ow);
            }
            let _ = udp.send_to(&buff[..body_len], addr).await;
        }
    }
    Ok(())
}
