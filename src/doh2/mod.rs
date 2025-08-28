use crate::{CONFIG, chttp::genrequrl, config, rule::rulecheck, tls, utils::Buffering};
use core::str;
use h2::client::SendRequest;
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::Mutex, time::sleep};

pub async fn http2(rules: std::sync::Arc<Option<Vec<crate::rule::Rule>>>) {
    // TLS Conf
    let h2tls = tls::tlsconf(vec![b"h2".to_vec()], CONFIG.disable_certificate_validation);

    let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());

    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    loop {
        log::info!("H2 connecting");
        let tls = crate::tls::dynamic_tls_conn_gen(&["h2"], h2tls.clone()).await;
        if tls.is_err() {
            log::error!("{}", tls.unwrap_err());
            sleep(std::time::Duration::from_secs(
                CONFIG.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }

        let (client, h2c) = h2::client::handshake(tls.unwrap()).await.unwrap();
        log::info!("H2 Connection Established");

        let dead_conn = Arc::new(Mutex::new(false));
        // h2 engine
        let dead_conn2 = dead_conn.clone();
        let watcher = tokio::spawn(async move {
            if let Err(e) = h2c.await {
                *dead_conn2.lock().await = true;
                log::error!("H2: {e}");
            }
        });

        if let Some((dns_query, query_size, addr)) = tank {
            let h2_conn_dead = dead_conn.clone();
            let udp = udp.clone();
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(e) = send_req((*dns_query, query_size), client, addr, udp).await {
                    log::error!("H2: {e}");
                    *h2_conn_dead.lock().await = true;
                }
            });
            tank = None;
        }

        let mut dns_query = [0u8; 512];
        loop {
            let h2_client = client.clone().ready().await;
            if let Err(e) = h2_client {
                log::error!("H2: {e}");
                break;
            }

            let h2_conn_dead = dead_conn.clone();
            let udp = udp.clone();
            if *h2_conn_dead.lock().await {
                watcher.abort();
                break;
            }

            let message = crate::keepalive::recv_timeout_with(
                &udp,
                CONFIG.connection_keep_alive,
                &mut dns_query,
                async {
                    let mut h2 = client.clone();
                    let req =
                        http::Request::get(format!("https://{}/", CONFIG.server_name.as_str()))
                            .body(())
                            .unwrap();
                    if let Err(e) = h2.send_request(req, true) {
                        log::error!("H2: {e}");
                        *h2_conn_dead.lock().await = true;
                    }
                },
            )
            .await;

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

                if *h2_conn_dead.lock().await {
                    tank = Some((Box::new(dns_query), query_size, addr));
                    watcher.abort();
                    break;
                }

                // Base64url dns query
                tokio::spawn(async move {
                    if let Err(e) =
                        send_req((dns_query, query_size), h2_client.unwrap(), addr, udp).await
                    {
                        log::error!("H2: {e}");
                        *h2_conn_dead.lock().await = true;
                    }
                });
            }
        }
    }
}

async fn send_req(
    dns_query: ([u8; 512], usize),
    mut h2_client: SendRequest<bytes::Bytes>,
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Sending request
    let mut resp = match CONFIG.http_method {
        config::HttpMethod::GET => {
            get(
                &mut h2_client,
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
            let mut p = h2_client.send_request(
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
            if CONFIG.overwrite.is_some() {
                let b: &[u8] = &body;
                let mut buff = [0; 1024 * 4];
                buff[..b.len()].copy_from_slice(b);
                crate::ipoverwrite::overwrite_ip(&mut buff[..b.len()], &CONFIG.overwrite);
                udp.send_to(&buff[..b.len()], addr).await?;
            } else {
                udp.send_to(&body, addr).await?;
            }
        }
    } else {
        log::error!(
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
) -> Result<http::Response<h2::RecvStream>, Box<dyn std::error::Error + Send + Sync>> {
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
