mod config;
mod doh2;
mod doh3;
mod doq;
mod dot;
mod fragment;
mod multi;
mod rule;
mod tls;
mod utils;

use core::str;
use std::sync::Arc;

use multi::h1_multi;
use rule::{convert_rules, rulecheck_sync, Rules};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};
use utils::{genrequrlh1, tcp_connect_handle};

#[tokio::main]
async fn main() {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    // Load config
    // If config file does not exist or malformed, panic occurs.
    let conf = config::load_config();
    // Convert rules to adjust domains like dns query and improve performance
    let rules = convert_rules(conf.rules);

    let v6 = conf.ipv6;
    let quic_conf_file_v6 = conf.quic.clone();
    let v6rules = rules.clone();
    tokio::spawn(async move {
        if v6.enable {
            match v6.protocol.as_str() {
                "h1 multi" => {
                    h1_multi(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await
                }
                "h1" => {
                    http1(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await
                }
                "h2" => {
                    doh2::http2(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await
                }
                "h3" => {
                    let connecting_timeout_sec = quic_conf_file_v6.connecting_timeout_sec;
                    doh3::http3(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        quic_conf_file_v6,
                        v6.noise,
                        connecting_timeout_sec,
                        conf.connection,
                        v6rules,
                    )
                    .await
                }
                "dot" => {
                    dot::dot(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await;
                }
                "dot nonblocking" => {
                    dot::dot_nonblocking(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await;
                }
                "doq" => {
                    let connecting_timeout_sec = quic_conf_file_v6.connecting_timeout_sec;
                    doq::doq(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        quic_conf_file_v6,
                        v6.noise,
                        connecting_timeout_sec,
                        conf.connection,
                        v6rules,
                    )
                    .await;
                }
                _ => {
                    println!("Invalid http version");
                    panic!();
                }
            }
        }
    });

    match conf.protocol.as_str() {
        "h1 multi" => {
            h1_multi(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await
        }
        "h1" => {
            http1(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await
        }
        "h2" => {
            doh2::http2(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await
        }
        "h3" => {
            let connecting_timeout_sec = conf.quic.connecting_timeout_sec;
            doh3::http3(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                conf.quic,
                conf.noise,
                connecting_timeout_sec,
                conf.connection,
                rules,
            )
            .await
        }
        "dot" => {
            dot::dot(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await;
        }
        "dot nonblocking" => {
            dot::dot_nonblocking(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await;
        }
        "doq" => {
            let connecting_timeout_sec = conf.quic.connecting_timeout_sec;
            doq::doq(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                conf.quic,
                conf.noise,
                connecting_timeout_sec,
                conf.connection,
                rules,
            )
            .await;
        }
        _ => {
            println!("Invalid http version");
            panic!();
        }
    }
}

async fn http1(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rule: Rules,
) {
    // TLS Client
    let ctls = tls::tlsconf(vec![b"http/1.1".to_vec()]);

    let mut retry = 0u8;
    loop {
        // TCP socket for TLS
        let tcp = tcp_connect_handle(socket_addrs).await;
        println!("New HTTP/1.1 connection");

        let example_com = (server_name.clone())
            .try_into()
            .expect("Invalid server name");
        // Perform TLS Client Hello fragmenting
        let tls_conn = tokio_rustls::TlsConnector::from(Arc::clone(&ctls))
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

        println!("HTTP/1.1 Connection Established");
        retry = 0;

        let mut c = tls_conn.unwrap();
        // UDP socket to listen for DNS query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        loop {
            let mut dns_query = [0u8; 512];
            let udp_ok = udp.recv_from(&mut dns_query).await;
            if udp_ok.is_err() {
                continue;
            }
            let (query_size, addr) = udp_ok.unwrap();
            // rule check
            if rule.enable && rulecheck_sync(&rule, (dns_query, query_size), addr, &udp).await {
                continue;
            }

            let mut temp = [0u8; 512];
            let query_bs4url =
                base64_url::encode_to_slice(&dns_query[..query_size], &mut temp).unwrap();
            let mut url = [0;1024];
            let http_req = genrequrlh1(&mut url, server_name.as_bytes(), query_bs4url);

            // Write http request
            if c.write(http_req).await.is_err() {
                println!("connection closed by peer");
                break;
            }

            // Handle Reciving Data
            let mut http_resp = [0; 2048];
            let http_resp_size = c.read(&mut http_resp).await.unwrap_or(0);

            // Break if failed to recv response
            if http_resp_size == 0 {
                break;
            }

            if let Some((x1, x2)) = catch_in_buff("\r\n\r\n".as_bytes(), &http_resp) {
                let body = &http_resp[x2..http_resp_size];

                let content_length = c_len(&http_resp[..x1]);
                if content_length != 0 && content_length == body.len() {
                    // Full body recved
                    let _ = udp.send_to(body, addr).await;
                } else if content_length != 0 && content_length > body.len() {
                    // There is another chunk of body
                    // We know it's not bigger than 512 bytes
                    let mut merged_body = [0;512];
                    merged_body[..body.len()].copy_from_slice(body);
                    if let Ok(b2_len) = c.read(&mut merged_body[body.len()..]).await{
                        let _ = udp.send_to(&merged_body[..body.len()+b2_len], addr).await;
                    }
                }
            }
        }
    }
}

fn c_len(http_head: &[u8]) -> usize {
    let content_length = b"content-length: ";
    for line in http_head.split(|&b| b == b'\r' || b == b'\n') {
        if let Some(pos) = line
            .windows(content_length.len())
            .position(|window| window.eq_ignore_ascii_case(content_length))
        {
            if let Ok(length) = std::str::from_utf8(&line[pos + content_length.len()..])
                .unwrap_or("0")
                .trim()
                .parse::<usize>()
            {
                return length;
            }
        }
    }
    0
}

fn catch_in_buff(find: &[u8], buff: &[u8]) -> Option<(usize, usize)> {
    buff.windows(find.len())
        .position(|pre| pre == find)
        .map(|a| (a, a + find.len()))
}
