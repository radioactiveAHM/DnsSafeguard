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
    let quic_conf_file_v6 = conf.quic.clone();
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
                3 => {
                    doh3::http3(
                        v6.server_name,
                        &v6.socket_addrs,
                        &v6.udp_socket_addrs,
                        quic_conf_file_v6,
                    )
                    .await
                }
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
        3 => {
            doh3::http3(
                conf.server_name,
                &conf.socket_addrs,
                &conf.udp_socket_addrs,
                conf.quic,
            )
            .await
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
        tls_handshake_retry = 0;

        let mut c = tls_conn.unwrap();
        // UDP socket to listen for DNS query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        loop {
            let mut dns_query = [0u8; 768];
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
                b"\r\nConnection: keep-alive\r\nAccept: application/dns-message\r\n\r\n",
            ]
            .concat();

            // Write http request
            if c.write(&http_req).await.is_err() {
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
                    udp.send_to(body, addr).await.unwrap_or(0);
                } else if content_length != 0 && content_length > body.len() {
                    // There is another chunk of body
                    // We know it's not bigger than 512 bytes
                    let mut b2 = [0; 512];
                    let b2_len = c.read(&mut b2).await.unwrap_or(0);

                    udp.send_to(&[body, &b2[..b2_len]].concat(), addr)
                        .await
                        .unwrap_or(0);
                }
            }
        }
    }
}

fn c_len(http_head: &[u8]) -> usize {
    for head in String::from_utf8_lossy(http_head).split("\r\n") {
        let lower_head = head.to_lowercase();
        if lower_head.contains("content-length") {
            return lower_head
                .split("content-length: ")
                .last()
                .unwrap_or("0")
                .parse::<usize>()
                .unwrap_or(0);
        }
    }
    0
}

fn catch_in_buff(find: &[u8], buff: &[u8]) -> Option<(usize, usize)> {
    let size = find.len();
    let mut index = size;
    for _ in &buff[size..] {
        if find == &buff[index - size..index] {
            return Some((index - size, index));
        }
        index = index + 1
    }
    None
}