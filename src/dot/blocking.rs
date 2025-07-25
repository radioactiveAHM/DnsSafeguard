use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

use crate::rule::rulecheck_sync;
use crate::utils::convert_two_u8s_to_u16_be;
use crate::{config, tls, utils::convert_u16_to_two_u8s_be};

pub async fn dot(
    sn: &'static str,
    disable_domain_sni: bool,
    dcv: bool,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    fragmenting: &config::Fragmenting,
    connection: config::Connection,
    rule: crate::Rules,
    network_interface: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) {
    let ctls = tls::tlsconf(vec![b"dot".to_vec()], dcv);
    let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
    let mut tank: Option<(Box<[u8; 514]>, usize, SocketAddr)> = None;
    loop {
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
        println!("DOT Connection Established");

        // Tls Client
        let mut conn = tls_conn.unwrap();

        let mut query = [0; 514];
        let mut resp_dot_query = [0; 4096];
        loop {
            if let Some((query, query_size, addr)) = &tank {
                if handler(
                    &mut conn,
                    &udp,
                    query.as_ref(),
                    &mut resp_dot_query,
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
            // Recv dns query
            if let Ok((query_size, addr)) = udp.recv_from(&mut query[2..]).await {
                // rule check
                if (rule.is_some()
                    && rulecheck_sync(&rule, &mut query[2..query_size + 2], addr, &udp).await)
                    || query_size < 12
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
                    ow,
                )
                .await
                {
                    println!("DoT: {e}");
                    tank = Some((Box::new(query), query_size, addr));
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
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) -> tokio::io::Result<()> {
    // Send DOT query
    let _ = conn.write(&query[..query_size + 2]).await?;

    // Recv DOT query
    let resp_dot_query_size = conn.read(resp_dot_query).await?;
    if resp_dot_query_size as u16
        == convert_two_u8s_to_u16_be([resp_dot_query[0], resp_dot_query[1]]) + 2
    {
        if ow.is_some() {
            crate::ipoverwrite::overwrite_ip(&mut resp_dot_query[..resp_dot_query_size], ow);
        }
        udp.send_to(&resp_dot_query[2..resp_dot_query_size], addr)
            .await?;
    }

    Ok(())
}
