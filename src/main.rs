#![allow(dead_code)]

mod config;
mod doh2;
mod doh3;
mod fragment;
mod tls;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    // Load config
    // If config file does not exist or malformed, panic occurs.
    let conf = config::load_config();

    let v6 = conf.ipv6;
    tokio::spawn(async move {
        if v6.enable {
            match v6.http_version {
                1 => {
                    http1(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                    )
                    .await
                }
                2 => {
                    doh2::http2(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        &v6.fragmenting,
                    )
                    .await
                }
                3 => doh3::http3(v6.server_name, &v6.socket_addrs, &v6.udp_socket_addrs).await,
                _ => {
                    println!("Invalid http version");
                    panic!();
                }
            }
        }
    });

    match conf.http_version {
        1 => {
            http1(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
            )
            .await
        }
        2 => {
            doh2::http2(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                &conf.fragmenting,
            )
            .await
        }
        3 => doh3::http3(conf.server_name, &conf.socket_addrs, &conf.udp_socket_addrs).await,
        _ => {
            println!("Invalid http version");
            panic!();
        }
    }
}

fn catch_in_buff(find: &[u8], buff: &[u8]) -> (usize, usize) {
    let size = find.len();
    let mut index = size;
    for _ in &buff[size..] {
        if find == &buff[index - size..index] {
            return (index - size, index);
        }
        index = index + 1
    }
    (0, 0)
}

async fn http1(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
) {
    // TLS Client
    let ctls = tls::tlsconf(vec![b"http/1.1".to_vec()]);

    let mut tls_handshake_retry = 0u8;
    loop {
        if tls_handshake_retry == 5 {
            println!("Cannot perform TLS handshake");
            panic!();
        }
        println!("New HTTP/1.1 connection");


        // TCP socket for TLS
        let tcp = tokio::net::TcpStream::connect(socket_addrs).await.unwrap();

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
                                _ => panic!("Invalid fragment method"),
                            }
                        });
                    });
                }
            })
            .await;
        if tls_conn.is_err() {
            println!("TLS handshake failed. Retry {}", tls_handshake_retry);
            tls_handshake_retry = tls_handshake_retry + 1;
            continue;
        }

        println!("HTTP/1.1 Connection Established");

        let mut c = tls_conn.unwrap();
        // UDP socket to listen for DNS query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        let mut dead_conn = false;
        loop {
            if dead_conn {
                println!("connection closed by peer");
                break;
            }
            let mut dns_query: [u8; 8196] = [0u8; 8196];
            let udp_ok = udp.recv_from(&mut dns_query).await;
            if udp_ok.is_err() {
                continue;
            }
            let (query_size, addr) = udp_ok.unwrap();
            let query_base64url = base64_url::encode(&dns_query[..query_size]);

            let http_req = [
                b"GET /dns-query?dns=",
                query_base64url.as_bytes(),
                b" HTTP/1.1\r\nHost: ",
                server_name.as_bytes(),
                b"\r\nAccept: application/dns-message\r\n\r\n"
            ]
            .concat();

            // Write http request
            if c.write(&http_req).await.is_err() {
                dead_conn = true;
                continue;
            }

            // Handle Reciving Data
            let mut http_resp = [0u8; 8196];
            let http_resp_size = c.read(&mut http_resp).await.unwrap_or(0);

            let body =
                &http_resp[catch_in_buff("\r\n\r\n".as_bytes(), &http_resp).1..http_resp_size];

            if body.is_empty() {
                continue;
            }
            udp.send_to(body, addr).await.unwrap_or(0);
        }
    }
}
