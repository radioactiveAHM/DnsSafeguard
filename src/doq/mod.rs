use std::{net::SocketAddr, sync::Arc};

use quinn::{RecvStream, SendStream};
use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
};

use crate::{
    config::{self, Noise},
    doh3::udp_setup,
    rule::rulecheck,
    utils::{convert_u16_to_two_u8s_be, SNI},
};

pub async fn doq(
    sn: SNI,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    quic_conf_file: config::Quic,
    noise: Noise,
    connecting_timeout_sec: u64,
    connection: config::Connection,
    rule: crate::Rules,
) {
    let arc_rule = Arc::new(rule);
    let mut endpoint = udp_setup(socket_addrs, noise.clone(), quic_conf_file.clone(), "doq").await;

    let mut retry = 0u8;

    loop {
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
            // on windows when pc goes sleep the endpoint config is fucked up
            endpoint = udp_setup(socket_addrs, noise.clone(), quic_conf_file.clone(), "doq").await;
            continue;
        }

        println!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint.connect(socket_addrs, sn.string()).unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(connecting_timeout_sec),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        println!("QUIC 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint.connect(socket_addrs, sn.string()).unwrap().await;
                        if conn.is_ok() {
                            println!("QUIC Connection Established");
                        }
                        conn
                    }
                },
            )
            .await;

            if let Ok(pending) = timing {
                pending
            } else {
                println!("Connecting timeout");
                retry += 1;
                continue;
            }
        };

        if conn.is_err() {
            println!("{}", conn.unwrap_err());
            retry += 1;
            sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
            continue;
        }

        let quic = conn.unwrap();

        // QUIC Connection Established
        retry = 0;

        let arc_udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());
        let dead_conn = Arc::new(Mutex::new(false));

        let mut dns_query = [0u8; 512];
        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let dead = dead_conn.clone();
            if *dead.lock().await || quic.close_reason().is_some() {
                println!("{}", quic.close_reason().unwrap());
                break;
            }

            // Recive dns query
            let udp = arc_udp.clone();

            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
                // rule check
                if arc_rule.is_some()
                    && rulecheck(arc_rule.clone(), (dns_query, query_size), addr, udp.clone()).await
                {
                    continue;
                }

                match quic.open_bi().await {
                    Ok(bistream) => {
                        tokio::spawn(async move {
                            let mut temp = false;
                            if let Err(e) =
                                send_dq(bistream, (dns_query, query_size), addr, udp).await
                            {
                                let e_str = e.to_string();
                                println!("{}", e_str);
                                temp = true;
                            }
                            if temp {
                                *(dead.lock().await) = true;
                            }
                        });
                    }
                    Err(conn_e) => {
                        println!("{conn_e}");
                        break;
                    }
                }
            }
        }
    }
}

async fn send_dq(
    (mut send, mut recv): (SendStream, RecvStream),
    dns_query: ([u8; 512], usize),
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut doq_query = [0u8; 514];
    [doq_query[0], doq_query[1]] = convert_u16_to_two_u8s_be(dns_query.1 as u16);
    doq_query[2..].copy_from_slice(&dns_query.0);

    send.write(&doq_query[..dns_query.1 + 2]).await?;
    send.finish()?;
    let mut buff = [0u8; 4096];
    if let Some(resp_size) = recv.read(&mut buff).await? {
        let _ = udp.send_to(&buff[2..resp_size], addr).await;
    }

    Ok(())
}
