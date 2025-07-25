use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::rule::rulecheck;
use crate::utils::{convert_two_u8s_to_u16_be, unsafe_staticref};
use crate::{config, tls, utils::convert_u16_to_two_u8s_be};

pub async fn dot_nonblocking(
    sn: &'static str,
    disable_domain_sni: bool,
    dcv: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rules: &Option<Vec<crate::rule::Rule>>,
    network_interface: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) {
    let ctls = tls::tlsconf(vec![b"dot".to_vec()], dcv);

    let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    loop {
        println!("DOT Non-Blocking Connecting");
        let tls_conn = tls::tls_conn_gen(
            sn.to_string(),
            disable_domain_sni,
            socket_addrs,
            fragmenting.clone(),
            ctls.clone(),
            connection,
            network_interface,
        )
        .await;
        if tls_conn.is_err() {
            println!("{}", tls_conn.unwrap_err());
            sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
            continue;
        }
        println!("DOT Non-Blocking Connection Established");

        // Tls Client
        let (mut conn_r, mut conn_w) = tokio::io::split(tls_conn.unwrap());
        // UDP Server to recv dns query

        // Hold dns message ID with it's dns resolver Addr to match
        let waiters: Arc<Mutex<std::collections::HashMap<u16, std::net::SocketAddr>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Task to Recv from DOT
        let arc_waiters = Arc::clone(&waiters);
        let task = tokio::spawn(async move {
            let waiters = arc_waiters;
            loop {
                // Recv DOT query
                let mut resp_dot_query = [0; 4096];
                if let Ok(resp_dot_query_size) = conn_r.read(&mut resp_dot_query).await {
                    if resp_dot_query_size as u16
                        == convert_two_u8s_to_u16_be([resp_dot_query[0], resp_dot_query[1]]) + 2
                    {
                        if let Some(addr) =
                            waiters.lock().await.remove(&convert_two_u8s_to_u16_be([
                                resp_dot_query[2],
                                resp_dot_query[3],
                            ]))
                        {
                            if ow.is_some() {
                                crate::ipoverwrite::overwrite_ip(
                                    &mut resp_dot_query[2..(resp_dot_query_size)],
                                    ow,
                                );
                            }
                            let _ = uudp
                                .send_to(&resp_dot_query[2..(resp_dot_query_size)], addr)
                                .await;
                        }
                    }
                } else {
                    break;
                }
            }
        });

        let mut query = [0; 514];
        loop {
            if task.is_finished() {
                println!("connection closed by peer");
                break;
            }
            // Recv dns query
            if let Ok((query_size, addr)) = udp.recv_from(&mut query[2..]).await {
                // rule check
                if (rules.is_some()
                    && rulecheck(
                        rules,
                        crate::rule::RuleDqt::Tls(query, query_size),
                        addr,
                        uudp,
                    )
                    .await)
                    || query_size < 12
                {
                    continue;
                }
                // DNS query with two u8 size which is required by DOT
                // Size of dns Query as two u8
                [query[0], query[1]] = convert_u16_to_two_u8s_be(query_size as u16);

                // Send DOT query
                if conn_w.write(&query[..query_size + 2]).await.is_ok() {
                    waiters
                        .lock()
                        .await
                        .insert(convert_two_u8s_to_u16_be([query[2], query[3]]), addr);
                } else {
                    println!("connection closed by peer");
                    task.abort();
                    break;
                }
            }
        }
    }
}
