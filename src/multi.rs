use crate::CONFIG;

type RcLocker = std::sync::Arc<
    tokio::sync::Mutex<tokio::sync::mpsc::Receiver<([u8; 512], usize, std::net::SocketAddr)>>,
>;

pub async fn h1_multi(rules: std::sync::Arc<Option<Vec<crate::rule::Rule>>>) {
    let ctls = crate::tls::tlsconf(
        vec![b"http/1.1".to_vec()],
        CONFIG.disable_certificate_validation,
    );

    let udp = crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap();
    let uudp = crate::utils::unsafe_staticref(&udp);

    let (sender, recver) = tokio::sync::mpsc::channel(CONFIG.connection.h1_multi_connections);
    let recver_locker: RcLocker = std::sync::Arc::new(tokio::sync::Mutex::new(recver));

    for conn_i in 0..CONFIG.connection.h1_multi_connections {
        let recver_locker = recver_locker.clone();
        let tls_config = ctls.clone();
        tokio::spawn(async move {
            loop {
                let tls_conn =
                    crate::tls::dynamic_tls_conn_gen(&["http/1.1"], tls_config.clone()).await;
                if tls_conn.is_err() {
                    log::error!("{}", tls_conn.unwrap_err());
                    tokio::time::sleep(std::time::Duration::from_secs(
                        CONFIG.connection.reconnect_sleep,
                    ))
                    .await;
                    continue;
                }
                log::info!("HTTP/1.1 Connection {conn_i} Established");
                let mut c = tls_conn.unwrap();

                let mut base64_url_temp = [0u8; 4096];
                let mut url = [0; 4096];
                let mut http_resp = vec![0; 1024 * 8];
                let mut bf_http_resp: tokio::io::ReadBuf<'_> =
                    tokio::io::ReadBuf::new(&mut http_resp);
                loop {
                    if let Some((query, size, addr)) = recver_locker.lock().await.recv().await
                        && let Err(e) = crate::h11::handler(
                            &mut c,
                            uudp,
                            &query[..size],
                            &mut base64_url_temp,
                            &mut url,
                            &mut bf_http_resp,
                            &addr,
                        )
                        .await
                    {
                        log::error!("HTTP/1.1 Connection {conn_i}: {e}");
                        break;
                    }
                }
            }
        });
    }

    let mut dns_query = [0u8; 512];
    loop {
        if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
            // rule check
            if (rules.is_some()
                && crate::rule::rulecheck(
                    rules.clone(),
                    crate::rule::RuleDqt::Http(dns_query, query_size),
                    addr,
                    uudp,
                )
                .await)
                || query_size < 12
            {
                continue;
            }
            let _ = sender.send((dns_query, query_size, addr)).await;
        }
    }
}
