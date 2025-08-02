use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};

use crate::{
    chttp::genrequrlh1,
    rule::rulecheck,
    tls::{self, tls_conn_gen},
    utils::{Buffering, c_len, catch_in_buff, unsafe_staticref},
};

type CrossContainer = (
    ([u8; 512], usize),
    std::net::SocketAddr,
    &'static tokio::net::UdpSocket,
);

pub async fn h1_multi(
    config: &'static crate::config::Config,
    rules: &Option<Vec<crate::rule::Rule>>,
) {
    // TLS Client Config
    let ctls = tls::tlsconf(
        vec![b"http/1.1".to_vec()],
        config.disable_certificate_validation,
    );

    // UDP Socket for DNS Query
    let udp = crate::udp::udp_socket(config.serve_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    // Channels to send DNS query to one of task with http/1.1 connection
    let (sender, recver) = crossbeam_channel::bounded(config.connection.h1_multi_connections);

    // Spawn Task for multiple connections
    for conn_i in 0..config.connection.h1_multi_connections {
        let recver_cln: crossbeam_channel::Receiver<CrossContainer> = recver.clone();
        let tls_config = ctls.clone();
        let frag = config.fragmenting.clone();
        tokio::spawn(async move {
            let task_rcv = recver_cln;
            loop {
                let tls_conn = tls_conn_gen(
                    config.server_name.clone(),
                    config.ip_as_sni,
                    config.serve_addrs,
                    frag.clone(),
                    tls_config.clone(),
                    config.connection,
                    &config.interface,
                )
                .await;
                if tls_conn.is_err() {
                    println!("{}", tls_conn.unwrap_err());
                    sleep(std::time::Duration::from_secs(
                        config.connection.reconnect_sleep,
                    ))
                    .await;
                    continue;
                }
                println!("HTTP/1.1 Connection {conn_i} Established");
                let mut c = tls_conn.unwrap();
                loop {
                    let mut package = Result::Err(crossbeam_channel::RecvError);
                    tokio::task::block_in_place(|| {
                        package = task_rcv.recv();
                    });
                    if let Ok((query, addr, udp)) = package {
                        // HTTP Req
                        let mut temp = [0u8; 4096];
                        let query_bs4url =
                            base64_url::encode_to_slice(&query.0[..query.1], &mut temp).unwrap();
                        let mut url = [0; 4096];
                        let mut b = Buffering(&mut url, 0);
                        let http_req = genrequrlh1(
                            &mut b,
                            config.server_name.as_bytes(),
                            query_bs4url,
                            &config.custom_http_path,
                        );

                        // Send HTTP Req
                        if c.write(http_req).await.is_err() {
                            println!("connection closed by peer");
                            break;
                        }

                        // Handle Reciving Data
                        let mut http_resp = [0; 4096];
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
                                if config.overwrite.is_some() {
                                    crate::ipoverwrite::overwrite_ip(
                                        &mut http_resp[x2..http_resp_size],
                                        &config.overwrite,
                                    );
                                }
                                let _ = udp.send_to(&http_resp[x2..http_resp_size], addr).await;
                            } else if content_length != 0 && content_length > body.len() {
                                // There is another chunk of body

                                if let Ok(size) =
                                    c.read(&mut http_resp[x2 + http_resp_size..]).await
                                {
                                    if config.overwrite.is_some() {
                                        crate::ipoverwrite::overwrite_ip(
                                            &mut http_resp[x2..http_resp_size + size],
                                            &config.overwrite,
                                        );
                                    }
                                    let _ = udp
                                        .send_to(&http_resp[x2..http_resp_size + size], addr)
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // Recv DNS queries and send to tasks using channel
    let mut dns_query = [0u8; 512];
    loop {
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
            tokio::task::block_in_place(|| {
                if sender.send(((dns_query, query_size), addr, uudp)).is_err() {
                    println!("Tasks are dead")
                }
            });
        }
    }
}
