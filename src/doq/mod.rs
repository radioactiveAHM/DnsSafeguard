use std::{net::SocketAddr, str::FromStr, sync::Arc};

use quinn::{RecvStream, SendStream};
use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
};

use crate::{
    config::{self, Noise},
    doh3::udp_setup,
    rule::rulecheck,
    utils::convert_u16_to_two_u8s_be,
};

pub async fn doq(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    quic_conf_file: config::Quic,
    noise: Noise,
    connecting_timeout_sec: u64,
    connection: config::Connection,
    rule: crate::Rules,
) {
    let arc_rule = Arc::new(rule);
    let socketadrs = SocketAddr::from_str(socket_addrs).unwrap();
    let mut endpoint = udp_setup(socketadrs, noise.clone(), quic_conf_file.clone(), "doq").await;

    let mut retry = 0u8;

    loop {
        if retry == connection.max_reconnect {
            println!("Max retry reached. Sleeping for 30 seconds");
            sleep(std::time::Duration::from_secs(
                connection.max_reconnect_sleep,
            ))
            .await;
            retry = 0;
            // on windows when pc goes sleep the endpoint config is fucked up
            endpoint = udp_setup(socketadrs, noise.clone(), quic_conf_file.clone(), "doq").await;
            continue;
        }

        println!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint.connect(socketadrs, server_name.as_str()).unwrap();

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
                        let conn = endpoint
                            .connect(
                                SocketAddr::from_str(socket_addrs).unwrap(),
                                server_name.as_str(),
                            )
                            .unwrap()
                            .await;
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

        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let dead = dead_conn.clone();
            if *dead.lock().await {
                break;
            }

            // Recive dns query
            let mut dns_query = [0u8; 512];
            let udp = arc_udp.clone();

            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
                // rule check
                if arc_rule.enable && rulecheck(arc_rule.clone(), (dns_query, query_size), addr, udp.clone()).await{
                    continue;
                }

                if let Ok(bistream) = quic.open_bi().await {
                    tokio::spawn(async move {
                        let mut temp = false;
                        if let Err(e) = send_dq(bistream, (dns_query, query_size), addr, udp).await
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
    let doq_size = convert_u16_to_two_u8s_be(dns_query.1 as u16);
    let doq_query = [&[doq_size[0], doq_size[1]], &dns_query.0[..dns_query.1]].concat();

    send.write(&doq_query).await?;
    send.finish()?;
    let mut buff = [0u8; 512];
    if let Some(resp_size) = recv.read(&mut buff).await? {
        let _ = udp.send_to(&buff[2..resp_size], addr).await;
    }

    Ok(())
}