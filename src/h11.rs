use core::str;
use std::{net::SocketAddr, sync::Arc};

use crate::chttp::genrequrlh1;
use crate::config::{Connection, Fragmenting};
use crate::rule::{rulecheck_sync, Rules};
use crate::tls::{self, tlsfragmenting};
use crate::utils::{c_len, catch_in_buff, tcp_connect_handle, Buffering, Sni};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};

pub async fn http1(
    sn: Sni,
    disable_domain_sni: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &Fragmenting,
    connection: Connection,
    rule: Rules,
    custom_http_path: Option<String>,
) {
    // TLS Client
    let ctls = tls::tlsconf(vec![b"http/1.1".to_vec()]);

    let mut retry = 0u8;
    loop {
        // TCP socket for TLS
        let tcp = tcp_connect_handle(socket_addrs, connection).await;
        println!("New HTTP/1.1 connection");

        let example_com = if disable_domain_sni {
            (socket_addrs.ip()).into()
        } else {
            sn.string()
                .to_string()
                .try_into()
                .expect("Invalid server name")
        };
        // Perform TLS Client Hello fragmenting
        let tls_conn = tokio_rustls::TlsConnector::from(Arc::clone(&ctls))
            .connect_with_stream(example_com, tcp, |tls, tcp| {
                // Do fragmenting
                if fragmenting.enable {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            tlsfragmenting(fragmenting, tls, tcp);
                        });
                    });
                }
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

        println!("HTTP/1.1 Connection Established");
        retry = 0;

        let mut c = tls_conn.unwrap();
        // UDP socket to listen for DNS query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
        let cpath: Option<&str> = custom_http_path.as_deref();

        let mut dns_query = [0u8; 512];
        let mut base64_url_temp = [0u8; 512];
        let mut url = [0; 1024];
        let mut http_resp = [0; 4096];
        loop {
            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
                // rule check
                if (rule.is_some()
                    && rulecheck_sync(&rule, &mut dns_query[..query_size], addr, &udp).await)
                    || query_size < 12
                {
                    continue;
                }

                if let Err(e) = handler(
                    &mut c,
                    &udp,
                    &cpath,
                    &sn,
                    &dns_query,
                    &mut base64_url_temp,
                    &mut url,
                    &mut http_resp,
                    &query_size,
                    &addr,
                )
                .await
                {
                    println!("HTTP/1.1: {e}");
                    break;
                }
            }
        }
    }
}

pub async fn handler(
    c: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    udp: &tokio::net::UdpSocket,
    cpath: &Option<&str>,
    sn: &Sni,
    dns_query: &[u8],
    base64_url_temp: &mut [u8],
    url: &mut [u8],
    http_resp: &mut [u8],
    query_size: &usize,
    addr: &SocketAddr,
) -> Result<(), std::io::Error> {
    let query_bs4url = {
        if let Ok(qbs4) = base64_url::encode_to_slice(&dns_query[..*query_size], base64_url_temp) {
            qbs4
        } else {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    };
    let mut b = Buffering(url, 0);
    let http_req = genrequrlh1(&mut b, sn.slice(), query_bs4url, cpath);

    // Write http request
    let _ = c.write(http_req).await?;

    // Handle Reciving Data
    let http_resp_size = c.read(http_resp).await?;
    if let Some((x1, x2)) = catch_in_buff(b"\r\n\r\n", http_resp) {
        let body = &http_resp[x2..http_resp_size];
        let content_length = c_len(&http_resp[..x1]);
        if content_length != 0 && content_length == body.len() {
            // Full body recved
            let _ = udp.send_to(body, addr).await;
        } else if content_length != 0 && content_length > body.len() {
            // There is another chunk of body
            // We know it's not bigger than 512 bytes
            let mut merged_body = [0; 4096];
            merged_body[..body.len()].copy_from_slice(body);
            if let Ok(b2_len) = c.read(&mut merged_body[body.len()..]).await {
                let _ = udp.send_to(&merged_body[..body.len() + b2_len], addr).await;
            }
        }
    }

    Ok(())
}
