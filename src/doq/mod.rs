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
    utils::{convert_u16_to_two_u8s_be, Sni},
};

pub async fn doq(
    sn: Sni,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    quic_conf_file: config::Quic,
    noise: Noise,
    connecting_timeout_sec: u64,
    connection: config::Connection,
    rule: crate::Rules,
) {
    let arc_rule: Option<Arc<Vec<crate::rule::Rule>>> = if rule.is_some() {
        Some(Arc::new(rule.unwrap()))
    } else {
        None
    };
    let mut endpoint = udp_setup(socket_addrs, noise.clone(), quic_conf_file.clone(), "doq").await;

    let arc_udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());
    let dead_conn = Arc::new(Mutex::new(false));

    let mut tank: Option<(Box<[u8; 514]>, usize, SocketAddr)> = None;

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

        let mut dns_query = [0u8; 514];
        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let dead = dead_conn.clone();

            if tank.is_some() {
                match quic.open_bi().await {
                    Ok(bistream) => {
                        let udp = arc_udp.clone();
                        let (dns_query, query_size, addr) = tank.unwrap();
                        tokio::spawn(async move {
                            let mut temp = false;
                            if let Err(e) =
                                send_dq(bistream, (*dns_query, query_size), addr, udp).await
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

                tank = None;
                continue;
            }

            // Recive dns query
            if let Ok((query_size, addr)) = arc_udp.recv_from(&mut dns_query[2..]).await {
                // rule check
                if (arc_rule.is_some()
                    && rulecheck(
                        arc_rule.clone(),
                        crate::rule::RuleDqt::Tls(dns_query, query_size),
                        addr,
                        arc_udp.clone(),
                    )
                    .await)
                    || query_size < 12
                {
                    continue;
                }

                if *dead.lock().await || quic.close_reason().is_some() {
                    println!("{}", quic.close_reason().unwrap());
                    tank = Some((Box::new(dns_query), query_size, addr));
                    break;
                }

                match quic.open_bi().await {
                    Ok(bistream) => {
                        let udp = arc_udp.clone();
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
    mut dns_query: ([u8; 514], usize),
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> tokio::io::Result<()> {
    [dns_query.0[0], dns_query.0[1]] = convert_u16_to_two_u8s_be(dns_query.1 as u16);

    send.write(&dns_query.0[..dns_query.1 + 2]).await?;
    send.finish()?;
    let mut buff = [0u8; 4096];
    if let Some(resp_size) = recv.read(&mut buff).await? {
        let _ = udp.send_to(&buff[2..resp_size], addr).await;
    }

    Ok(())
}
