use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::rule::{rulecheck, rulecheck_sync};
use crate::utils::convert_two_u8s_to_u16_be;
use crate::{config, multi::tls_conn_gen, tls, utils::convert_u16_to_two_u8s_be};

pub async fn dot(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rule: crate::Rules,
) {
    let ctls = tls::tlsconf(vec![b"dot".to_vec()]);
    let mut retry = 0u8;
    loop {
        let tls_conn = tls_conn_gen(
            server_name.clone(),
            socket_addrs.to_string(),
            fragmenting.clone(),
            ctls.clone(),
        )
        .await;
        if tls_conn.is_err() {
            if retry == connection.max_reconnect {
                println!("Max retry reached. Sleeping for 1Min");
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
        println!("DOT Connection Established");
        retry = 0;

        // Tls Client
        let mut conn = tls_conn.unwrap();
        // UDP Server to recv dns query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        loop {
            // Recv dns query
            let mut query = [0; 512];
            if let Ok((query_size, addr)) = udp.recv_from(&mut query).await {
                // rule check
                if rule.enable && rulecheck_sync(&rule, (query,query_size), addr, &udp).await {
                    continue;
                }
                // DNS query with two u8 size which is required by DOT
                // Size of dns Query as two u8
                let mut dot_query = [0u8;514];
                [dot_query[0], dot_query[1]] = convert_u16_to_two_u8s_be(query_size as u16);
                dot_query[2..].copy_from_slice(&query);

                // Send DOT query
                if conn.write(&dot_query[..query_size+2]).await.is_err() {
                    // Connection is closed
                    println!("connection closed by peer");
                    break;
                }

                // Recv DOT query
                let mut resp_dot_query = [0; 514];
                if let Ok(resp_dot_query_size) = conn.read(&mut resp_dot_query).await {
                    udp.send_to(&resp_dot_query[2..(resp_dot_query_size)], addr)
                        .await
                        .unwrap_or(0);
                } else {
                    // Connection is closed
                    println!("connection closed by peer");
                    break;
                }
            }
        }
    }
}

pub async fn dot_nonblocking(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rule: crate::Rules,
) {
    let arc_rule = Arc::new(rule);
    let ctls = tls::tlsconf(vec![b"dot".to_vec()]);
    let mut retry = 0u8;
    loop {
        if retry == 5 {
            panic!();
        }
        let tls_conn = tls_conn_gen(
            server_name.clone(),
            socket_addrs.to_string(),
            fragmenting.clone(),
            ctls.clone(),
        )
        .await;
        if tls_conn.is_err() {
            if retry == connection.max_reconnect {
                println!("Max retry reached. Sleeping for 1Min");
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
        println!("DOT Non-Blocking Connection Established");
        retry = 0;

        // Tls Client
        let (mut conn_r, mut conn_w) = tokio::io::split(tls_conn.unwrap());
        // UDP Server to recv dns query
        let udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());

        // Hold dns message ID with it's dns resolver Addr to match
        let waiters: Arc<Mutex<Vec<(u16, std::net::SocketAddr)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Task to Recv from DOT
        let arc_waiters = Arc::clone(&waiters);
        let arc_udp = udp.clone();
        let task = tokio::spawn(async move {
            let waiters = arc_waiters;
            let udp = arc_udp;
            loop {
                // Recv DOT query
                let mut resp_dot_query = [0; 512];
                if let Ok(resp_dot_query_size) = conn_r.read(&mut resp_dot_query).await {
                    let query = &resp_dot_query[2..(resp_dot_query_size)];
                    let query_id = convert_two_u8s_to_u16_be([query[0], query[1]]);

                    // match the response with DNS message ID
                    let mut waiters_lock = waiters.lock().await;
                    if let Some(waiter) =
                        waiters_lock.iter().position(|waiter| waiter.0 == query_id)
                    {
                        let _ = udp.send_to(query, waiters_lock[waiter].1).await;
                        waiters_lock.swap_remove(waiter);
                    }
                } else {
                    break;
                }
            }
        });

        loop {
            if task.is_finished() {
                println!("connection closed by peer");
                break;
            }
            // Recv dns query
            let mut query = [0; 512];
            if let Ok((query_size, addr)) = udp.recv_from(&mut query).await {
                // rule check
                if arc_rule.enable && rulecheck(arc_rule.clone(), (query,query_size), addr, udp.clone()).await {
                    continue;
                }
                // DNS query with two u8 size which is required by DOT
                // Size of dns Query as two u8
                let mut dot_query = [0u8;514];
                [dot_query[0], dot_query[1]] = convert_u16_to_two_u8s_be(query_size as u16);
                dot_query[2..].copy_from_slice(&query);

                // Send DOT query
                if conn_w.write(&dot_query[..query_size+2]).await.is_err() {
                    // Connection is closed
                    println!("connection closed by peer");
                    task.abort();
                    break;
                }

                // Push DNS message ID and UDP resolver addr to waiter
                waiters
                    .lock()
                    .await
                    .push((convert_two_u8s_to_u16_be([query[0], query[1]]), addr))
            }
        }
    }
}
