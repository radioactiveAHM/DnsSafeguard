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
    CONFIG,
    chttp::genrequrl,
    config::{self, Noise},
    rule::rulecheck,
    utils::Buffering,
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

pub async fn http3(rules: std::sync::Arc<Option<Vec<crate::rule::Rule>>>) {
    let mut endpoint = udp_setup(
        CONFIG.remote_addrs,
        &CONFIG.noise,
        &CONFIG.quic,
        "h3",
        &CONFIG.interface,
    )
    .await;

    let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());

    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let mut connecting_retry = 0u8;
    loop {
        if connecting_retry == 3 {
            connecting_retry = 0;
            endpoint = udp_setup(
                CONFIG.remote_addrs,
                &CONFIG.noise,
                &CONFIG.quic,
                "h3",
                &CONFIG.interface,
            )
            .await;
        }
        log::info!("HTTP/3 Connecting");
        // Connect to dns server
        let connecting = endpoint
            .connect(CONFIG.remote_addrs, &CONFIG.server_name)
            .unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(CONFIG.quic.connecting_timeout),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        log::info!("HTTP/3 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint
                            .connect(CONFIG.remote_addrs, &CONFIG.server_name)
                            .unwrap()
                            .await;
                        if conn.is_ok() {
                            log::info!("HTTP/3 Connection Established");
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
                log::error!("H3: Connecting timeout");
                sleep(std::time::Duration::from_secs(
                    CONFIG.connection.reconnect_sleep,
                ))
                .await;
                continue;
            }
        };

        if conn.is_err() {
            connecting_retry += 1;
            log::error!("H3: {}", conn.unwrap_err());
            sleep(std::time::Duration::from_secs(
                CONFIG.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        connecting_retry = 0;

        let (mut h3c, h3) = match h3::client::new(h3_quinn::Connection::new(conn.unwrap())).await {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("H3: {e}");
                continue;
            }
        };

        let dead_conn = Arc::new(Mutex::new(false));

        let dead_conn2 = dead_conn.clone();
        let watcher = tokio::spawn(async move {
            log::error!("H3: {}", h3c.wait_idle().await);
            *(dead_conn2.lock().await) = true;
        });

        let mut dns_query = [0u8; 512];
        loop {
            let quic_conn_dead = dead_conn.clone();
            let udp = udp.clone();

            if let Some((dns_query, query_size, addr)) = tank {
                let h3 = h3.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_request(h3, (*dns_query, query_size), addr, udp).await {
                        log::error!("H3 Stream: {e}");
                        temp = true;
                    }
                    if temp {
                        *(quic_conn_dead.lock().await) = true;
                    }
                });

                tank = None;
                continue;
            }

            let message = if let Some(dur) = CONFIG.connection_keep_alive {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(dur),
                    udp.recv_from(&mut dns_query),
                )
                .await
                {
                    Ok(message) => Some(message),
                    Err(_) => {
                        let mut h3 = h3.clone();
                        let req =
                            http::Request::get(format!("https://{}/", CONFIG.server_name.as_str()))
                                .body(())
                                .unwrap();
                        if let Err(e) = h3.send_request(req).await {
                            log::error!("H3: {e}");
                            *(quic_conn_dead.lock().await) = true;
                        }
                        None
                    }
                }
            } else {
                Some(udp.recv_from(&mut dns_query).await)
            };

            if let Some(Ok((query_size, addr))) = message {
                // rule check
                if (rules.is_some()
                    && rulecheck(
                        rules.clone(),
                        crate::rule::RuleDqt::Http(dns_query, query_size),
                        addr,
                        udp.clone(),
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
                    if let Err(e) = send_request(h3, (dns_query, query_size), addr, udp).await {
                        log::error!("H3 Stream: {e}");
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
    mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    dns_query: ([u8; 512], usize),
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reqs = match CONFIG.http_method {
        config::HttpMethod::GET => {
            get(
                &mut h3,
                &CONFIG.server_name,
                &CONFIG.custom_http_path,
                dns_query,
            )
            .await?
        }
        config::HttpMethod::POST => {
            let p = if let Some(path) = &CONFIG.custom_http_path {
                path.as_str()
            } else {
                "/dns-query"
            };
            let mut pending = h3
                .send_request(
                    http::Request::post(
                        http::Uri::builder()
                            .scheme("https")
                            .authority(CONFIG.server_name.as_str())
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

    let resp = timeout(
        std::time::Duration::from_secs(CONFIG.response_timeout),
        reqs.recv_response(),
    )
    .await??;

    let clen: usize = if let Some(clen) = resp.headers().get("content-length") {
        clen.to_str().unwrap_or("0").parse().unwrap_or(0)
    } else {
        0
    };

    if resp.status() == http::status::StatusCode::OK {
        let mut buff = [0; 1024 * 8];
        let mut body_len = 0;
        if let Some(body) = reqs.recv_data().await? {
            body_len += body.reader().read(&mut buff)?;
        }

        if clen > 0 {
            loop {
                if body_len >= clen {
                    break;
                }
                if let Some(body) = reqs.recv_data().await? {
                    body_len += body.reader().read(&mut buff[body_len..])?;
                } else {
                    break;
                }
            }
        }

        if CONFIG.overwrite.is_some() {
            crate::ipoverwrite::overwrite_ip(&mut buff[..body_len], &CONFIG.overwrite);
        }
        let _ = udp.send_to(&buff[..body_len], addr).await;
    } else {
        log::error!(
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
