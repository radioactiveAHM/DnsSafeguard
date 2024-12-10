use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::rule::{rulecheck, rulecheck_sync};
use crate::utils::{convert_two_u8s_to_u16_be, Sni};
use crate::{config, multi::tls_conn_gen, tls, utils::convert_u16_to_two_u8s_be};

pub async fn dot(
    sn: Sni,
    disable_domain_sni: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rule: crate::Rules,
) {
    let ctls = tls::tlsconf(vec![b"dot".to_vec()]);
    let mut retry = 0u8;
    loop {
        let tls_conn = tls_conn_gen(
            sn.string().to_string(),
            disable_domain_sni,
            socket_addrs,
            fragmenting.clone(),
            ctls.clone(),
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
        println!("DOT Connection Established");
        retry = 0;

        // Tls Client
        let mut conn = tls_conn.unwrap();
        // UDP Server to recv dns query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        let mut query = [0; 514];
        let mut resp_dot_query = [0; 4096];
        loop {
            // Recv dns query
            if let Ok((query_size, addr)) = udp.recv_from(&mut query[2..]).await {
                // rule check
                if rule.is_some()
                    && rulecheck_sync(&rule, &query[2..query_size + 2], addr, &udp).await
                {
                    continue;
                }
                // DNS query with two u8 size which is required by DOT
                // Size of dns Query as two u8
                [query[0], query[1]] = convert_u16_to_two_u8s_be(query_size as u16);

                // Send DOT query
                if conn.write(&query[..query_size + 2]).await.is_err() {
                    // Connection is closed
                    println!("connection closed by peer");
                    break;
                }

                // Recv DOT query
                if let Ok(resp_dot_query_size) = conn.read(&mut resp_dot_query).await {
                    if resp_dot_query_size as u16
                        == convert_two_u8s_to_u16_be([resp_dot_query[0], resp_dot_query[1]]) + 2
                    {
                        let _ = udp
                            .send_to(&resp_dot_query[2..(resp_dot_query_size)], addr)
                            .await;
                    }
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
    sn: Sni,
    disable_domain_sni: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
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
            sn.string().to_string(),
            disable_domain_sni,
            socket_addrs,
            fragmenting.clone(),
            ctls.clone(),
            connection,
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
        let waiters: Arc<Mutex<Vec<(u16, std::net::SocketAddr, Instant)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Task to Recv from DOT
        let arc_waiters = Arc::clone(&waiters);
        let arc_udp = udp.clone();
        let task = tokio::spawn(async move {
            let waiters = arc_waiters;
            let udp = arc_udp;
            loop {
                // Recv DOT query
                let mut resp_dot_query = [0; 4096];
                if let Ok(resp_dot_query_size) = conn_r.read(&mut resp_dot_query).await {
                    if resp_dot_query_size as u16
                        == convert_two_u8s_to_u16_be([resp_dot_query[0], resp_dot_query[1]]) + 2
                    {
                        let query = &resp_dot_query[2..(resp_dot_query_size)];

                        // match the response with DNS message ID
                        let mut waiters_lock = waiters.lock().await;
                        if let Some(waiter) = waiters_lock.iter().position(|waiter| {
                            waiter.0 == convert_two_u8s_to_u16_be([query[0], query[1]])
                        }) {
                            let _ = udp.send_to(query, waiters_lock.swap_remove(waiter).1).await;
                        }
                    }
                } else {
                    break;
                }
            }
        });

        let waiters_cleanup = waiters.clone();
        let cleaner_task = tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(
                    connection.dot_nonblocking_dns_query_lifetime,
                ))
                .await;
                let mut waiters_cleanup_lock = waiters_cleanup.lock().await;
                if waiters_cleanup_lock.len() > 0 {
                    waiters_cleanup_lock.retain(|waiter| {
                        waiter.2.elapsed().as_secs() < connection.dot_nonblocking_dns_query_lifetime
                    });
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
                if arc_rule.is_some()
                    && rulecheck(
                        arc_rule.clone(),
                        crate::rule::RuleDqt::Tls(query, query_size),
                        addr,
                        udp.clone(),
                    )
                    .await
                {
                    continue;
                }
                // DNS query with two u8 size which is required by DOT
                // Size of dns Query as two u8
                [query[0], query[1]] = convert_u16_to_two_u8s_be(query_size as u16);

                // Push DNS message ID and UDP resolver addr to waiter
                let mut waiters_lock = waiters.lock().await;
                waiters_lock.push((
                    convert_two_u8s_to_u16_be([query[2], query[3]]),
                    addr,
                    tokio::time::Instant::now(),
                ));

                // Send DOT query
                if conn_w.write(&query[..query_size + 2]).await.is_err() {
                    // Connection is closed
                    println!("connection closed by peer");
                    task.abort();
                    cleaner_task.abort();
                    waiters_lock.pop();
                    break;
                }
            }
        }
    }
}
