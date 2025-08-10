mod noise;
pub mod qtls;
pub mod transporter;

use core::str;
use std::{io::Read, net::SocketAddr, sync::Arc};

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

pub async fn client_noise(addr: SocketAddr, target: SocketAddr, noise: &Noise) -> quinn::Endpoint {
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

    let runtime = quinn::default_runtime().unwrap();
    let ep = quinn::EndpointConfig::default();
    quinn::Endpoint::new_with_abstract_socket(
        ep,
        None,
        runtime.wrap_udp_socket(socket.into()).unwrap(),
        runtime,
    )
    .unwrap()
}

pub async fn udp_setup(
    target: SocketAddr,
    noise: &Noise,
    quic_conf_file: &crate::config::Quic,
    alpn: &str,
    network_interface: &'static Option<String>,
) -> quinn::Endpoint {
    let mut endpoint = client_noise(
        crate::udp::udp_addr_to_bind(network_interface, target.is_ipv4()),
        target,
        noise,
    )
    .await;
    endpoint.set_default_client_config(
        quinn::ClientConfig::new(qtls::qtls(alpn))
            .transport_config(transporter::tc(quic_conf_file))
            .to_owned(),
    );

    endpoint
}

pub async fn http3(config: &'static crate::config::Config, rules: &Option<Vec<crate::rule::Rule>>) {
    let mut endpoint = udp_setup(
        config.remote_addrs,
        &config.noise,
        &config.quic,
        "h3",
        &config.interface,
    )
    .await;

    let udp = crate::udp::udp_socket(config.serve_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let mut connecting_retry = 0u8;
    loop {
        if connecting_retry == 3 {
            connecting_retry = 0;
            endpoint = udp_setup(
                config.remote_addrs,
                &config.noise,
                &config.quic,
                "h3",
                &config.interface,
            )
            .await;
        }
        println!("HTTP/3 Connecting");
        // Connect to dns server
        let connecting = endpoint
            .connect(config.remote_addrs, &config.server_name)
            .unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(config.quic.connecting_timeout_sec),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        println!("HTTP/3 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint
                            .connect(config.remote_addrs, &config.server_name)
                            .unwrap()
                            .await;
                        if conn.is_ok() {
                            println!("HTTP/3 Connection Established");
                        }
                        conn
                    }
                },
            )
            .await;

            if let Ok(pending) = timing {
                pending
            } else {
                connecting_retry += 1;
                println!("Connecting timeout");
                sleep(std::time::Duration::from_secs(
                    config.connection.reconnect_sleep,
                ))
                .await;
                continue;
            }
        };

        if conn.is_err() {
            connecting_retry += 1;
            println!("{}", conn.unwrap_err());
            sleep(std::time::Duration::from_secs(
                config.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        connecting_retry = 0;

        let (mut h3c, h3) = match h3::client::new(h3_quinn::Connection::new(conn.unwrap())).await {
            Ok(conn) => conn,
            Err(e) => {
                println!("H3: {e}");
                continue;
            }
        };
        let dead_conn = Arc::new(Mutex::new(false));

        let dead_conn2 = dead_conn.clone();
        let watcher = tokio::spawn(async move {
            println!("H3: {}", h3c.wait_idle().await);
            *(dead_conn2.lock().await) = true;
        });

        let mut dns_query = [0u8; 512];
        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let quic_conn_dead = dead_conn.clone();

            if let Some((dns_query, query_size, addr)) = tank {
                let h3 = h3.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_request(
                        &config.server_name,
                        h3,
                        (*dns_query, query_size),
                        addr,
                        uudp,
                        &config.custom_http_path,
                        &config.overwrite,
                        config.http_method,
                        config.response_timeout,
                    )
                    .await
                    {
                        println!("H3 Stream: {e}");
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
                    watcher.abort();
                    break;
                }

                let h3 = h3.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_request(
                        &config.server_name,
                        h3,
                        (dns_query, query_size),
                        addr,
                        uudp,
                        &config.custom_http_path,
                        &config.overwrite,
                        config.http_method,
                        config.response_timeout,
                    )
                    .await
                    {
                        println!("H3 Stream: {e}");
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
    response_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reqs = match hm {
        config::HttpMethod::GET => get(&mut h3, server_name, cpath, dns_query).await?,
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

    let resp = timeout(std::time::Duration::from_secs(response_timeout), async {
        reqs.recv_response().await
    })
    .await??;

    if resp.status() == http::status::StatusCode::OK {
        if let Some(body) = reqs.recv_data().await? {
            let mut buff = [0; 4096];
            let body_len = body.reader().read(&mut buff)?;
            if ow.is_some() {
                crate::ipoverwrite::overwrite_ip(&mut buff[..body_len], ow);
            }
            let _ = udp.send_to(&buff[..body_len], addr).await;
        }
    } else {
        println!(
            "H3 Stream: Remote responded with status code of {}",
            resp.status().as_str()
        );
    }

    Ok(())
}

#[inline(never)]
async fn get(
    h3: &mut SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    server_name: &'static str,
    ucpath: &'static Option<String>,
    dns_query: ([u8; 512], usize),
) -> Result<
    h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    Box<dyn std::error::Error>,
> {
    let mut temp = [0u8; 512];
    let mut url = [0; 1024];
    let r = h3
        .send_request(
            http::Request::get(genrequrl(
                &mut Buffering(&mut url, 0),
                server_name.as_bytes(),
                base64_url::encode_to_slice(&dns_query.0[..dns_query.1], &mut temp)?,
                ucpath,
            )?)
            .version(http::Version::HTTP_3)
            .header("Accept", "application/dns-message")
            .body(())?,
        )
        .await?;
    Ok(r)
}
