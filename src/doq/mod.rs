use std::{net::SocketAddr, sync::Arc};

use quinn::{RecvStream, SendStream};
use tokio::{
    io::ReadBuf,
    sync::Mutex,
    time::{sleep, timeout},
};

use crate::{
    config::{self, Noise},
    doh3::udp_setup,
    rule::rulecheck,
    utils::{convert_u16_to_two_u8s_be, unsafe_staticref},
};

pub async fn doq(
    sn: &'static str,
    socket_addrs: SocketAddr,
    udp_socket_addrs: SocketAddr,
    quic_conf_file: config::Quic,
    noise: Noise,
    connection: config::Connection,
    rules: &Option<Vec<crate::rule::Rule>>,
    network_interface: &'static Option<String>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) {
    let mut endpoint = udp_setup(
        socket_addrs,
        &noise,
        &quic_conf_file,
        "doq",
        network_interface,
    )
    .await;

    let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    let dead_conn = Arc::new(Mutex::new(false));

    let mut tank: Option<(Box<[u8; 514]>, usize, SocketAddr)> = None;

    let mut connecting_retry = 0u8;
    loop {
        if connecting_retry == 5 {
            endpoint = udp_setup(
                socket_addrs,
                &noise,
                &quic_conf_file,
                "doq",
                network_interface,
            )
            .await;
        }
        println!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint.connect(socket_addrs, sn).unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(quic_conf_file.connecting_timeout_sec),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        println!("QUIC 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint.connect(socket_addrs, sn).unwrap().await;
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
                connecting_retry += 1;
                println!("Connecting timeout");
                sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
                continue;
            }
        };

        if conn.is_err() {
            connecting_retry += 1;
            println!("{}", conn.unwrap_err());
            sleep(std::time::Duration::from_secs(connection.reconnect_sleep)).await;
            continue;
        }

        let quic = conn.unwrap();

        let mut dns_query = [0u8; 514];
        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let dead = dead_conn.clone();

            if tank.is_some() {
                match quic.open_bi().await {
                    Ok(bistream) => {
                        let (dns_query, query_size, addr) = tank.unwrap();
                        tokio::spawn(async move {
                            let mut temp = false;
                            if let Err(e) =
                                send_dq(bistream, (*dns_query, query_size), addr, uudp, ow).await
                            {
                                let e_str = e.to_string();
                                println!("{e_str}");
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
            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query[2..]).await {
                // rule check
                if (rules.is_some()
                    && rulecheck(
                        rules,
                        crate::rule::RuleDqt::Tls(dns_query, query_size),
                        addr,
                        uudp,
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
                        let udp = uudp;
                        tokio::spawn(async move {
                            let mut temp = false;
                            if let Err(e) =
                                send_dq(bistream, (dns_query, query_size), addr, udp, ow).await
                            {
                                let e_str = e.to_string();
                                println!("{e_str}");
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
        endpoint.wait_idle().await;
    }
}

async fn send_dq(
    (mut send, mut recv): (SendStream, RecvStream),
    mut dns_query: ([u8; 514], usize),
    addr: SocketAddr,
    udp: &'static tokio::net::UdpSocket,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
) -> tokio::io::Result<()> {
    [dns_query.0[0], dns_query.0[1]] = convert_u16_to_two_u8s_be(dns_query.1 as u16);
    send.write(&dns_query.0[..dns_query.1 + 2]).await?;
    send.finish()?;
    let mut buff = [0u8; 4096];
    let mut rb = ReadBuf::new(&mut buff);
    std::future::poll_fn(|cx| recv.poll_read_buf(cx, &mut rb)).await?;
    if ow.is_some() {
        crate::ipoverwrite::overwrite_ip(&mut rb.filled_mut()[2..], ow);
    }
    let _ = udp.send_to(&rb.filled()[2..], addr).await;
    Ok(())
}
