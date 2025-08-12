use crate::chttp::genrequrl;
use crate::rule::rulecheck;
use crate::tls::tlsfragmenting;
use crate::utils::Buffering;
use crate::utils::unsafe_staticref;
use core::str;
use h2::client::SendRequest;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config;
use crate::interface::tcp_connect_handle;
use crate::tls;

pub async fn http2(config: &'static crate::config::Config, rules: &Option<Vec<crate::rule::Rule>>) {
    // TLS Conf
    let h2tls = tls::tlsconf(vec![b"h2".to_vec()], config.disable_certificate_validation);

    let udp = crate::udp::udp_socket(config.serve_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    loop {
        // TCP Connection
        // Panic if socket_addrs invalid
        let tcp =
            tcp_connect_handle(config.remote_addrs, config.connection, &config.interface).await;
        println!("New H2 connection");

        let example_com = if config.ip_as_sni {
            (config.remote_addrs.ip()).into()
        } else {
            config
                .server_name
                .to_string()
                .try_into()
                .expect("Invalid server name")
        };
        // TLS Client
        let tls_conn = tokio_rustls::TlsConnector::from(Arc::clone(&h2tls))
            .connect_with_stream(example_com, tcp, |tls, tcp| {
                // Do fragmenting
                tlsfragmenting(&config.fragmenting, tls, tcp);
            })
            .await;
        if tls_conn.is_err() {
            println!("{}", tls_conn.unwrap_err());
            sleep(std::time::Duration::from_secs(
                config.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }

        let (client, h2c) = h2::client::handshake(tls_conn.unwrap()).await.unwrap();
        println!("H2 Connection Established");

        let dead_conn = Arc::new(Mutex::new(false));
        // h2 engine
        let dead_conn2 = dead_conn.clone();
        let watcher = tokio::spawn(async move {
            if let Err(e) = h2c.await {
                *(dead_conn2.lock().await) = true;
                println!("H2: {e}");
            }
        });

        if let Some(dur) = config.http_keep_alive {
            let dead_conn3 = dead_conn.clone();
            let client2 = client.clone();
            tokio::spawn(async move {
                loop {
                    let req =
                        http::Request::get(format!("https://{}/", config.server_name.as_str()))
                            .body(())
                            .unwrap();
                    if let Err(e) = client2.clone().send_request(req, true) {
                        println!("H2: {e}");
                        *(dead_conn3.lock().await) = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(dur)).await;
                }
            });
        }

        let mut dns_query = [0u8; 512];
        loop {
            let h2_client = client.clone().ready().await;
            if let Err(e) = h2_client {
                println!("H2: {e}");
                break;
            }
            // Check if Connection is dead
            let h2_conn_dead = dead_conn.clone();

            if let Some((dns_query, query_size, addr)) = tank {
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_req(
                        &config.server_name,
                        (*dns_query, query_size),
                        h2_client.unwrap(),
                        addr,
                        uudp,
                        &config.custom_http_path,
                        &config.overwrite,
                        config.http_method,
                    )
                    .await
                    {
                        println!("{e}");
                        temp = true;
                        // for some weird reason if i try to lock dead_conn_arc here error occur
                    }
                    if temp {
                        *(h2_conn_dead.lock().await) = true;
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

                if *h2_conn_dead.lock().await {
                    tank = Some((Box::new(dns_query), query_size, addr));
                    watcher.abort();
                    break;
                }

                // Base64url dns query
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_req(
                        &config.server_name,
                        (dns_query, query_size),
                        h2_client.unwrap(),
                        addr,
                        uudp,
                        &config.custom_http_path,
                        &config.overwrite,
                        config.http_method,
                    )
                    .await
                    {
                        println!("{e}");
                        temp = true;
                        // for some weird reason if i try to lock dead_conn_arc here error occur
                    }
                    if temp {
                        *(h2_conn_dead.lock().await) = true;
                    }
                });
            }
        }
    }
}

async fn send_req(
    server_name: &'static str,
    dns_query: ([u8; 512], usize),
    mut h2_client: SendRequest<bytes::Bytes>,
    addr: SocketAddr,
    udp: &'static tokio::net::UdpSocket,
    ucpath: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
    hm: config::HttpMethod,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sending request
    let mut resp = match hm {
        config::HttpMethod::GET => get(&mut h2_client, server_name, ucpath, dns_query).await?,
        config::HttpMethod::POST => {
            let p = if let Some(path) = ucpath {
                path.as_str()
            } else {
                "/dns-query"
            };
            let mut p = h2_client.send_request(
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
                .version(http::Version::HTTP_2)
                .body(())?,
                false,
            )?;
            crate::dohserver::h2p::h2_send_bytes(&mut p.1, &dns_query.0[..dns_query.1]).await?;
            p.0.await?
        }
    };

    if resp.status() == http::status::StatusCode::OK {
        if let Some(Ok(body)) = resp.body_mut().data().await {
            if ow.is_some() {
                let b: &[u8] = &body;
                let mut buff = [0; 1024 * 4];
                buff[..b.len()].copy_from_slice(b);
                crate::ipoverwrite::overwrite_ip(&mut buff[..b.len()], ow);
                udp.send_to(&buff[..b.len()], addr).await?;
            } else {
                udp.send_to(&body, addr).await?;
            }
        }
    } else {
        println!(
            "H2 Stream: Remote responded with status code of {}",
            resp.status().as_str()
        );
    }

    Ok(())
}

#[inline(never)]
async fn get(
    h2_client: &mut SendRequest<bytes::Bytes>,
    server_name: &'static str,
    ucpath: &'static Option<String>,
    dns_query: ([u8; 512], usize),
) -> Result<http::Response<h2::RecvStream>, Box<dyn std::error::Error>> {
    let mut temp = [0u8; 512];
    let mut url = [0u8; 1024];
    let r = h2_client
        .send_request(
            http::Request::get(genrequrl(
                &mut Buffering(&mut url, 0),
                server_name.as_bytes(),
                base64_url::encode_to_slice(&dns_query.0[..dns_query.1], &mut temp)?,
                ucpath,
            )?)
            .version(http::Version::HTTP_2)
            .header("Accept", "application/dns-message")
            .body(())?,
            true,
        )?
        .0
        .await?;
    Ok(r)
}
