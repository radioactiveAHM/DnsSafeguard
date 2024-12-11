mod noise;
pub mod qtls;
pub mod transporter;

use core::str;
use std::{borrow::BorrowMut, future, io::Read, net::SocketAddr, str::FromStr, sync::Arc};

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
    utils::{Buffering, Sni},
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
    noise::noiser(noise, target, &socket).await;

    let runtime = quinn::default_runtime()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no async runtime found"))
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
    socketadrs: SocketAddr,
    noise: Noise,
    quic_conf_file: crate::config::Quic,
    alpn: &str,
) -> quinn::Endpoint {
    let qaddress = {
        if socketadrs.is_ipv4() {
            SocketAddr::from_str("0.0.0.0:0").unwrap()
        } else if socketadrs.is_ipv6() {
            SocketAddr::from_str("[::]:0").unwrap()
        } else {
            panic!()
        }
    };
    // UDP socket as endpoint for quic
    let mut endpoint = {
        if noise.enable {
            client_noise(qaddress, socketadrs, noise).await
        } else {
            quinn::Endpoint::client(qaddress).unwrap()
        }
    };
    // Setup QUIC connection (QUIC Config)
    endpoint.set_default_client_config(
        quinn::ClientConfig::new(qtls::qtls(alpn))
            .transport_config(transporter::tc(quic_conf_file))
            .to_owned(),
    );

    endpoint
}

pub async fn http3(
    sn: Sni,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    quic_conf_file: config::Quic,
    noise: Noise,
    connecting_timeout_sec: u64,
    connection: config::Connection,
    rule: crate::Rules,
    custom_http_path: Option<String>,
) {
    let arc_rule = Arc::new(rule);
    let mut endpoint = udp_setup(socket_addrs, noise.clone(), quic_conf_file.clone(), "h3").await;

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
            endpoint = udp_setup(socket_addrs, noise.clone(), quic_conf_file.clone(), "h3").await;
            continue;
        }

        println!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint.connect(socket_addrs, sn.string()).unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(connecting_timeout_sec),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        println!("QUIC 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint.connect(socket_addrs, sn.string()).unwrap().await;
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
            Ok::<(), Box<dyn std::error::Error + Send>>(())
        };

        tokio::spawn(drive);

        // UDP socket to listen for DNS query
        // prepare for atomic
        let arc_udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());
        let cpath: Option<Arc<str>> = if custom_http_path.is_some() {
            Some(custom_http_path.clone().unwrap().into())
        } else {
            None
        };

        let mut dns_query = [0u8; 512];
        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let quic_conn_dead = dead_conn.clone();
            if *quic_conn_dead.lock().await {
                break;
            }

            // Recive dns query
            let udp = arc_udp.clone();

            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
                // rule check
                if arc_rule.is_some()
                    && rulecheck(
                        arc_rule.clone(),
                        crate::rule::RuleDqt::Http(dns_query, query_size),
                        addr,
                        udp.clone(),
                    )
                    .await
                {
                    continue;
                }

                let h3 = h3.clone();
                let cpath = cpath.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) =
                        send_request(sn, h3, (dns_query, query_size), addr, udp, cpath).await
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
    server_name: Sni,
    mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    dns_query: ([u8; 512], usize),
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
    cpath: Option<Arc<str>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut temp = [0u8; 512];
    let query_bs4url = base64_url::encode_to_slice(&dns_query.0[..dns_query.1], &mut temp)?;
    let mut url = [0; 1024];
    let mut b = Buffering(&mut url, 0);
    let req = http::Request::get(genrequrl(&mut b, server_name.slice(), query_bs4url, cpath)?)
        .header("Accept", "application/dns-message")
        .body(())?;

    // Send HTTP request
    let mut reqs = h3.borrow_mut().send_request(req).await?;
    reqs.finish().await?;

    // HTTP respones
    let resp: http::Response<()> = reqs.recv_response().await?;

    if resp.status() == http::status::StatusCode::OK {
        // get body
        if let Some(body) = reqs.recv_data().await? {
            let mut buff = [0; 4096];
            let body_len = body.reader().read(&mut buff)?;
            let _ = udp.send_to(&buff[..body_len], addr).await;
        }
    }
    Ok(())
}
