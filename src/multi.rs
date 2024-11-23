use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::sleep,
};

use crate::{
    c_len, catch_in_buff,
    chttp::genrequrlh1,
    config::{self, Connection},
    rule::rulecheck,
    tls::{self, tlsfragmenting},
    utils::{tcp_connect_handle, SNI},
};

type CrossContainer = (
    ([u8; 512], usize),
    std::net::SocketAddr,
    Arc<tokio::net::UdpSocket>,
);

pub async fn h1_multi(
    sn: SNI,
    disable_domain_sni: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &config::Fragmenting,
    connection: Connection,
    rule: crate::Rules,
    custom_http_path: Option<String>,
) {
    let arc_rule = Arc::new(rule);
    // TLS Client Config
    let ctls = tls::tlsconf(vec![b"http/1.1".to_vec()]);

    // UDP Socket for DNS Query
    let udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());

    // Channels to send DNS query to one of task with http/1.1 connection
    let (sender, recver) = crossbeam_channel::bounded(connection.h1_multi_connections as usize);

    // Spawn Task for multiple connections
    for conn_i in 0u8..connection.h1_multi_connections {
        let recver_cln: crossbeam_channel::Receiver<CrossContainer> = recver.clone();
        let tls_config = ctls.clone();
        let frag = (*fragmenting).clone();
        let custom_http_path = custom_http_path.clone();
        tokio::spawn(async move {
            let task_rcv = recver_cln;
            let mut retry = 0u8;
            loop {
                let tls_conn = tls_conn_gen(
                    sn.string().to_string(),
                    disable_domain_sni,
                    socket_addrs,
                    frag.clone(),
                    tls_config.clone(),
                    connection,
                )
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
                println!("HTTP/1.1 Connection {} Established", conn_i);
                retry = 0;
                let mut c = tls_conn.unwrap();
                let cpath: Option<&str> = custom_http_path.as_deref();
                loop {
                    let mut package = Result::Err(crossbeam_channel::RecvError);
                    tokio::task::block_in_place(|| {
                        package = task_rcv.recv();
                    });
                    if let Ok((query, addr, udp)) = package {
                        // HTTP Req
                        let mut temp = [0u8; 512];
                        let query_bs4url =
                            base64_url::encode_to_slice(&query.0[..query.1], &mut temp).unwrap();
                        let mut url = [0; 1024];
                        let http_req = genrequrlh1(&mut url, sn.slice(), query_bs4url, &cpath);

                        // Send HTTP Req
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
        });
    }

    // Recv DNS queries and send to tasks using channel
    loop {
        let mut dns_query = [0u8; 512];
        let udp_arc = udp.clone();

        if let Ok((query_size, addr)) = udp_arc.recv_from(&mut dns_query).await {
            // rule check
            if arc_rule.is_some()
                && rulecheck(
                    arc_rule.clone(),
                    (dns_query, query_size),
                    addr,
                    udp_arc.clone(),
                )
                .await
            {
                continue;
            }

            tokio::task::block_in_place(|| {
                if sender
                    .send(((dns_query, query_size), addr, udp_arc))
                    .is_err()
                {
                    println!("Tasks are dead")
                }
            });
        }
    }
}

pub async fn tls_conn_gen(
    server_name: String,
    disable_domain_sni: bool,
    socket_addrs: SocketAddr,
    fragmenting: config::Fragmenting,
    ctls: Arc<tokio_rustls::rustls::ClientConfig>,
    connection_cfg: Connection,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    let example_com = if disable_domain_sni {
        (socket_addrs.ip()).into()
    } else {
        (server_name).try_into().expect("Invalid server name")
    };

    tokio_rustls::TlsConnector::from(ctls)
        .connect_with_stream(
            example_com,
            tcp_connect_handle(socket_addrs, connection_cfg).await,
            |tls, tcp| {
                // Do fragmenting
                if fragmenting.enable {
                    tokio::task::block_in_place(|| {
                        tlsfragmenting(&fragmenting, tls, tcp);
                    });
                }
            },
        )
        .await
}
