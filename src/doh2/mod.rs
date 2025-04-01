use crate::chttp::genrequrl;
use crate::rule::rulecheck;
use crate::tls::tlsfragmenting;
use crate::utils::Buffering;
use crate::utils::unsafe_staticref;
use bytes::Bytes;
use core::str;
use h2::client::SendRequest;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config;
use crate::interface::tcp_connect_handle;
use crate::tls;

pub async fn http2(
    sn: &'static str,
    disable_domain_sni: bool,
    dcv: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rules: &Option<Vec<crate::rule::Rule>>,
    ucpath: &'static Option<String>,
    network_interface: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
    hm: config::HttpMethod,
) {
    // TLS Conf
    let h2tls = tls::tlsconf(vec![b"h2".to_vec()], dcv);

    let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let mut retry = 0u8;
    loop {
        // TCP Connection
        // Panic if socket_addrs invalid
        let tcp = tcp_connect_handle(socket_addrs, connection, network_interface).await;
        println!("New H2 connection");

        let example_com = if disable_domain_sni {
            (socket_addrs.ip()).into()
        } else {
            sn.to_string().try_into().expect("Invalid server name")
        };
        // TLS Client
        let tls_conn = tokio_rustls::TlsConnector::from(Arc::clone(&h2tls))
            .connect_with_stream(example_com, tcp, |tls, tcp| {
                // Do fragmenting
                tlsfragmenting(fragmenting, tls, tcp);
            })
            .await;
        if tls_conn.is_err() {
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
                continue;
            }
            println!("{}", tls_conn.unwrap_err());
            retry += 1;
            sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
            continue;
        }

        let (client, h2_) = h2::client::handshake(tls_conn.unwrap()).await.unwrap();
        println!("H2 Connection Established");
        retry = 0;

        let dead_conn = Arc::new(Mutex::new(false));

        // handle h2 low level connection
        let dead_conn_h2 = dead_conn.clone();
        tokio::spawn(async move {
            if let Err(e) = h2_.await {
                *(dead_conn_h2.lock().await) = true;
                println!("GOT ERR={:?}", e);
            }
        });

        let mut dns_query = [0u8; 512];
        loop {
            // Check if Connection is dead
            let h2_conn_dead = dead_conn.clone();

            if let Some((dns_query, query_size, addr)) = tank {
                let h2_client = client.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_req(
                        sn,
                        (*dns_query, query_size),
                        h2_client,
                        addr,
                        uudp,
                        ucpath,
                        ow,
                        hm,
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
                    break;
                }

                // Base64url dns query
                let h2_client = client.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_req(
                        sn,
                        (dns_query, query_size),
                        h2_client,
                        addr,
                        uudp,
                        ucpath,
                        ow,
                        hm,
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
    let resp = match hm {
        config::HttpMethod::GET => {
            let mut temp = [0u8; 512];
            let mut url = [0u8; 1024];
            h2_client
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
                .await?
        }
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
            p.1.reserve_capacity(dns_query.1);
            crate::dohserver::h2p::WaitForCap(&mut p.1).await?;
            p.1.send_data(Bytes::copy_from_slice(&dns_query.0[..dns_query.1]), true)?;
            p.0.await?
        }
    };

    if resp.status() == http::status::StatusCode::OK {
        // Get body (dns query)
        if let Some(body) = resp.into_body().data().await {
            let body_b = body?;
            if ow.is_some() {
                let b: &[u8] = &body_b;
                let mut buff = [0; 4196];
                buff[..b.len()].copy_from_slice(b);
                crate::ipoverwrite::overwrite_ip(&mut buff[..b.len()], ow);
                udp.send_to(&buff[..b.len()], addr).await?;
            } else {
                udp.send_to(&body_b, addr).await?;
            }
        }
    }
    Ok(())
}
