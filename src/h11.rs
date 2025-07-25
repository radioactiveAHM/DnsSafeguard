use core::str;
use std::{net::SocketAddr, sync::Arc};

use crate::chttp::genrequrlh1;
use crate::config::{Connection, Fragmenting};
use crate::interface::tcp_connect_handle;
use crate::rule::{Rules, rulecheck_sync};
use crate::tls::{self, tlsfragmenting};
use crate::utils::{Buffering, c_len, catch_in_buff};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};

pub async fn http1(
    sn: &'static str,
    disable_domain_sni: bool,
    dcv: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &Fragmenting,
    connection: Connection,
    rule: Rules,
    ucpath: &'static Option<String>,
    network_interface: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) {
    // TLS Client
    let ctls = tls::tlsconf(vec![b"http/1.1".to_vec()], dcv);
    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
    loop {
        // TCP socket for TLS
        let tcp = tcp_connect_handle(socket_addrs, connection, network_interface).await;
        println!("New HTTP/1.1 connection");

        let example_com = if disable_domain_sni {
            (socket_addrs.ip()).into()
        } else {
            sn.to_string().try_into().expect("Invalid server name")
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
            println!("{}", tls_conn.unwrap_err());
            sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
            continue;
        }
        println!("HTTP/1.1 Connection Established");

        let mut c = tls_conn.unwrap();

        let mut dns_query = [0u8; 512];
        let mut base64_url_temp = [0u8; 512];
        let mut url = [0; 1024];
        let mut http_resp = [0; 4096];
        loop {
            if let Some((dns_query, query_size, addr)) = &tank {
                if handler(
                    &mut c,
                    &udp,
                    ucpath,
                    sn,
                    dns_query.as_ref(),
                    &mut base64_url_temp,
                    &mut url,
                    &mut http_resp,
                    query_size,
                    addr,
                    ow,
                )
                .await
                .is_ok()
                {
                    tank = None;
                }
                continue;
            }
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
                    ucpath,
                    sn,
                    &dns_query,
                    &mut base64_url_temp,
                    &mut url,
                    &mut http_resp,
                    &query_size,
                    &addr,
                    ow,
                )
                .await
                {
                    println!("HTTP/1.1: {e}");
                    tank = Some((Box::new(dns_query), query_size, addr));
                    break;
                }
            }
        }
    }
}

pub async fn handler(
    c: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    udp: &tokio::net::UdpSocket,
    ucpath: &'static Option<String>,
    sn: &'static str,
    dns_query: &[u8],
    base64_url_temp: &mut [u8],
    url: &mut [u8],
    http_resp: &mut [u8],
    query_size: &usize,
    addr: &SocketAddr,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) -> tokio::io::Result<()> {
    let query_bs4url = match base64_url::encode_to_slice(&dns_query[..*query_size], base64_url_temp)
    {
        Ok(bs4) => bs4,
        Err(e) => {
            return Err(tokio::io::Error::other(e));
        }
    };
    let mut b = Buffering(url, 0);
    let http_req = genrequrlh1(&mut b, sn.as_bytes(), query_bs4url, ucpath);

    // Write http request
    let _ = c.write(http_req).await?;

    // Handle Reciving Data
    let http_resp_size = c.read(http_resp).await?;
    if let Some((x1, x2)) = catch_in_buff(b"\r\n\r\n", http_resp) {
        let body = &http_resp[x2..http_resp_size];
        let content_length = c_len(&http_resp[..x1]);
        if content_length != 0 && content_length == body.len() {
            // Full body recved
            if ow.is_some() {
                crate::ipoverwrite::overwrite_ip(&mut http_resp[x2..http_resp_size], ow);
            }
            let _ = udp.send_to(&http_resp[x2..http_resp_size], addr).await;
        } else if content_length != 0 && content_length > body.len() {
            // There is another chunk of body
            let size = c.read(&mut http_resp[x2 + http_resp_size..]).await?;
            if ow.is_some() {
                crate::ipoverwrite::overwrite_ip(&mut http_resp[x2..http_resp_size + size], ow);
            }
            let _ = udp
                .send_to(&http_resp[x2..http_resp_size + size], addr)
                .await;
        }
    }

    Ok(())
}
