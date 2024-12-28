use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

use crate::rule::rulecheck_sync;
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

                if let Err(e) = handler(
                    &mut conn,
                    &udp,
                    &query,
                    &mut resp_dot_query,
                    &query_size,
                    &addr,
                )
                .await
                {
                    println!("DoT: {e}");
                    break;
                }
            }
        }
    }
}

async fn handler(
    conn: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    udp: &tokio::net::UdpSocket,
    query: &[u8],
    resp_dot_query: &mut [u8],
    query_size: &usize,
    addr: &SocketAddr,
) -> Result<(), std::io::Error> {
    // Send DOT query
    let _ = conn.write(&query[..query_size + 2]).await?;

    // Recv DOT query
    let resp_dot_query_size = conn.read(resp_dot_query).await?;
    if resp_dot_query_size as u16
        == convert_two_u8s_to_u16_be([resp_dot_query[0], resp_dot_query[1]]) + 2
    {
        udp.send_to(&resp_dot_query[2..(resp_dot_query_size)], addr)
            .await?;
    }

    Ok(())
}
