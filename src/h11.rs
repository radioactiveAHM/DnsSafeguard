use core::str;
use std::net::SocketAddr;

use crate::chttp::genrequrlh1;
use crate::rule::{Rules, rulecheck_sync};
use crate::utils::{Buffering, c_len, catch_in_buff};
use tokio::{io::AsyncWriteExt, time::sleep};

pub async fn http1(config: &'static crate::config::Config, rule: Rules) {
    // TLS Client
    let ctls = crate::tls::tlsconf(
        vec![b"http/1.1".to_vec()],
        config.disable_certificate_validation,
    );
    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let udp = crate::udp::udp_socket(config.serve_addrs).await.unwrap();
    loop {
        println!("HTTP/1.1 Connecting");
        let tls = crate::tls::tls_conn_gen(
            config.server_name.to_string(),
            config.ip_as_sni,
            config.remote_addrs,
            config.fragmenting.clone(),
            ctls.clone(),
            config.connection,
            &config.interface,
        )
        .await;
        if tls.is_err() {
            println!("{}", tls.unwrap_err());
            sleep(std::time::Duration::from_secs(
                config.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        println!("HTTP/1.1 Connection Established");

        let mut tls = tls.unwrap();

        let mut dns_query = [0u8; 512];
        let mut base64_url_temp = [0u8; 1024 * 2];
        let mut url = [0; 1024 * 2];

        let mut http_resp = vec![0; 1024 * 8];
        let mut bf_http_resp: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut http_resp);
        loop {
            if let Some((dns_query, query_size, addr)) = &tank {
                if handler(
                    &mut tls,
                    &udp,
                    &config.custom_http_path,
                    &config.server_name,
                    dns_query.as_ref(),
                    &mut base64_url_temp,
                    &mut url,
                    &mut bf_http_resp,
                    query_size,
                    addr,
                    &config.overwrite,
                    config.response_timeout,
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
                    &mut tls,
                    &udp,
                    &config.custom_http_path,
                    &config.server_name,
                    &dns_query,
                    &mut base64_url_temp,
                    &mut url,
                    &mut bf_http_resp,
                    &query_size,
                    &addr,
                    &config.overwrite,
                    config.response_timeout,
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
    bf_http_resp: &mut tokio::io::ReadBuf<'_>,
    query_size: &usize,
    addr: &SocketAddr,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
    timeout: u64,
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

    let _ = c.write(http_req).await?;

    // Handle Reciving Data
    bf_http_resp.clear();
    crate::ioutils::read_buffered_timeout(bf_http_resp, c, std::time::Duration::from_secs(timeout))
        .await?;
    let mut http_resp_size = bf_http_resp.filled().len();
    let mut http_resp = bf_http_resp.filled_mut();
    if let Some((heads_end, body_start)) = catch_in_buff(b"\r\n\r\n", http_resp) {
        let content_length = c_len(&http_resp[..heads_end]);
        if content_length == 0 {
            return Err(tokio::io::Error::other("no content-length header"));
        }

        loop {
            let body = &http_resp[body_start..http_resp_size];
            if content_length == body.len() {
                break;
            } else {
                crate::ioutils::read_buffered_timeout(
                    bf_http_resp,
                    c,
                    std::time::Duration::from_secs(timeout),
                )
                .await?;
            }
            http_resp_size = bf_http_resp.filled().len();
            http_resp = bf_http_resp.filled_mut();
        }

        if ow.is_some() {
            crate::ipoverwrite::overwrite_ip(&mut http_resp[body_start..http_resp_size], ow);
        }
        let _ = udp
            .send_to(&http_resp[body_start..http_resp_size], addr)
            .await;
    } else {
        return Err(tokio::io::Error::other("Mailformed http response"));
    }

    Ok(())
}
