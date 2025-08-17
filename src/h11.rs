use std::net::SocketAddr;

use crate::{
    CONFIG,
    chttp::genrequrlh1,
    utils::{Buffering, c_len, catch_in_buff},
};
use tokio::{io::AsyncWriteExt, time::sleep};

pub async fn http1(rules: std::sync::Arc<Option<Vec<crate::rule::Rule>>>) {
    // TLS Client
    let ctls = crate::tls::tlsconf(
        vec![b"http/1.1".to_vec()],
        CONFIG.disable_certificate_validation,
    );
    let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;

    let udp = crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap();
    loop {
        log::info!("HTTP/1.1 Connecting");
        let tls = crate::tls::dynamic_tls_conn_gen(&["http/1.1"], ctls.clone()).await;
        if tls.is_err() {
            log::error!("{}", tls.unwrap_err());
            sleep(std::time::Duration::from_secs(
                CONFIG.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        log::info!("HTTP/1.1 Connection Established");

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
                    &dns_query[..*query_size],
                    &mut base64_url_temp,
                    &mut url,
                    &mut bf_http_resp,
                    addr,
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
                if (rules.is_some()
                    && crate::rule::rulecheck_sync(
                        &rules,
                        &mut dns_query[..query_size],
                        addr,
                        &udp,
                    )
                    .await)
                    || query_size < 12
                {
                    continue;
                }

                if let Err(e) = handler(
                    &mut tls,
                    &udp,
                    &dns_query[..query_size],
                    &mut base64_url_temp,
                    &mut url,
                    &mut bf_http_resp,
                    &addr,
                )
                .await
                {
                    log::error!("HTTP/1.1: {e}");
                    tank = Some((Box::new(dns_query), query_size, addr));
                    break;
                }
            }
        }
    }
}

#[inline(always)]
pub async fn handler<IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    c: &mut IO,
    udp: &tokio::net::UdpSocket,
    dns_query: &[u8],
    base64_url_temp: &mut [u8],
    url: &mut [u8],
    bf_http_resp: &mut tokio::io::ReadBuf<'_>,
    addr: &SocketAddr,
) -> tokio::io::Result<()> {
    let query_bs4url = match base64_url::encode_to_slice(&dns_query, base64_url_temp) {
        Ok(bs4) => bs4,
        Err(e) => {
            return Err(tokio::io::Error::other(e));
        }
    };
    let mut b = Buffering(url, 0);
    let http_req = genrequrlh1(
        &mut b,
        CONFIG.server_name.as_bytes(),
        query_bs4url,
        &CONFIG.custom_http_path,
    );

    let _ = c.write(http_req).await?;

    // Handle Reciving Data
    bf_http_resp.clear();
    crate::ioutils::read_buffered_timeout(
        bf_http_resp,
        c,
        std::time::Duration::from_secs(CONFIG.response_timeout),
    )
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
                    std::time::Duration::from_secs(CONFIG.response_timeout),
                )
                .await?;
            }
            http_resp_size = bf_http_resp.filled().len();
            http_resp = bf_http_resp.filled_mut();
        }

        if CONFIG.overwrite.is_some() {
            crate::ipoverwrite::overwrite_ip(
                &mut http_resp[body_start..http_resp_size],
                &CONFIG.overwrite,
            );
        }
        let _ = udp
            .send_to(&http_resp[body_start..http_resp_size], addr)
            .await;
    } else {
        return Err(tokio::io::Error::other("Mailformed http response"));
    }

    Ok(())
}
