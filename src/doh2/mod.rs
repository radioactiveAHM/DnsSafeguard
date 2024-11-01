use crate::fragment;
use crate::rule::rulecheck;
use crate::chttp::genrequrl;
use h2::client::SendRequest;
use core::str;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config;
use crate::tls;
use crate::utils::tcp_connect_handle;

pub async fn http2(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rule: crate::Rules,
    custom_http_path: String
) {
    let arc_rule = Arc::new(rule);
    // TLS Conf
    let h2tls = tls::tlsconf(vec![b"h2".to_vec()]);
    let mut retry = 0u8;
    loop {
        // TCP Connection
        // Panic if socket_addrs invalid
        let tcp = tcp_connect_handle(socket_addrs).await;
        println!("New H2 connection");

        let example_com = (server_name.clone())
            .try_into()
            .expect("Invalid server name");
        // TLS Client
        let tls_conn = tokio_rustls::TlsConnector::from(Arc::clone(&h2tls))
            .connect_with_stream(example_com, tcp, |tls, tcp| {
                // Do fragmenting
                if fragmenting.enable {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            match fragmenting.method.as_str() {
                                "linear" => fragment::fragment_client_hello(tls, tcp).await,
                                "random" => fragment::fragment_client_hello_rand(tls, tcp).await,
                                "single" => fragment::fragment_client_hello_pack(tls, tcp).await,
                                "jump" => fragment::fragment_client_hello_jump(tls, tcp).await,
                                _ => panic!("Invalid fragment method"),
                            }
                        });
                    });
                }
            })
            .await;
        if tls_conn.is_err() {
            if retry == connection.max_reconnect {
                println!("Max retry reached. Sleeping for 1Min");
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

        // UDP socket to listen for DNS query
        // prepare atomic
        let arc_udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());
        let arc_sn: Arc<str> = server_name.clone().into();
        let cpath: Option<Arc<str>> = if custom_http_path.len()>0{
            Some(custom_http_path.clone().into())
        }else {
            None
        };

        loop {
            // Check if Connection is dead
            let h2_conn_dead = dead_conn.clone();
            if *h2_conn_dead.lock().await {
                break;
            }

            // Recive dns query
            let mut dns_query = [0u8; 512];
            let udp_arc = arc_udp.clone();

            if let Ok((query_size, addr)) = udp_arc.recv_from(&mut dns_query).await {
                // rule check
                if arc_rule.enable && rulecheck(arc_rule.clone(), (dns_query,query_size), addr, udp_arc.clone()).await{
                    continue;
                }

                // Base64url dns query
                let h2_client = client.clone();
                let sn = arc_sn.clone();
                let cpath = cpath.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_req(sn, (dns_query, query_size), h2_client, addr, udp_arc, cpath).await {
                        let error = e.to_string();
                        println!("{}", error);
                        temp = true;
                        // for some weird reason if i try to lock dead_conn_arc here error occur
                    }
                    if temp {
                        *(h2_conn_dead.lock().await) = true;
                    }
                });
            } else {
                println!("Failed to recv DNS Query");
            }
        }
    }
}

async fn send_req(
    server_name: Arc<str>,
    dns_query: ([u8; 512], usize),
    mut h2_client: SendRequest<bytes::Bytes>,
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
    cpath: Option<Arc<str>>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut temp = [0u8;512];
    let query_bs4url = base64_url::encode_to_slice(&dns_query.0[..dns_query.1], &mut temp)?;
    // HTTP Request
    let mut url = [0;1024];
    let req = http::Request::get(genrequrl(&mut url, server_name.as_bytes(), query_bs4url,cpath))
    .header("Accept", "application/dns-message")
    .body(())?;

    // Sending request
    let resp = h2_client.send_request(req, true)?.0.await?;

    if resp.status() == http::status::StatusCode::OK {
        // Get body (dns query)
        if let Some(body) = resp.into_body().data().await {
            udp.send_to(&body?, addr).await?;
        }
    }
    Ok(())
}
