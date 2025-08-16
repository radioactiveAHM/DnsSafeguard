use std::{net::SocketAddr, sync::Arc};

use quinn::{RecvStream, SendStream};
use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
};

use crate::{
    doh3::udp_setup,
    rule::rulecheck,
    utils::{convert_two_u8s_to_u16_be, convert_u16_to_two_u8s_be, unsafe_staticref},
};

pub async fn doq(config: &'static crate::config::Config, rules: &Option<Vec<crate::rule::Rule>>) {
    let mut endpoint = udp_setup(
        config.remote_addrs,
        &config.noise,
        &config.quic,
        "doq",
        &config.interface,
    )
    .await;

    let udp = crate::udp::udp_socket(config.serve_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);

    let mut tank: Option<(Box<[u8; 514]>, usize, SocketAddr)> = None;

    let mut connecting_retry = 0u8;
    loop {
        if connecting_retry == 3 {
            connecting_retry = 0;
            endpoint = udp_setup(
                config.remote_addrs,
                &config.noise,
                &config.quic,
                "doq",
                &config.interface,
            )
            .await;
        }
        log::info!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint
            .connect(config.remote_addrs, &config.server_name)
            .unwrap();

        let conn = {
            let timing = timeout(
                std::time::Duration::from_secs(config.quic.connecting_timeout),
                async {
                    let connecting = connecting.into_0rtt();
                    if let Ok((conn, rtt)) = connecting {
                        rtt.await;
                        log::info!("QUIC 0RTT Connection Established");
                        Ok(conn)
                    } else {
                        let conn = endpoint
                            .connect(config.remote_addrs, &config.server_name)
                            .unwrap()
                            .await;
                        if conn.is_ok() {
                            log::info!("QUIC Connection Established");
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
                log::error!("DoQ: Connecting timeout");
                sleep(std::time::Duration::from_secs(
                    config.connection.reconnect_sleep,
                ))
                .await;
                continue;
            }
        };

        if conn.is_err() {
            connecting_retry += 1;
            log::error!("DoQ: {}", conn.unwrap_err());
            sleep(std::time::Duration::from_secs(
                config.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        connecting_retry = 0;

        let quic = conn.unwrap();
        let dead_conn = Arc::new(Mutex::new(false));

        let q2 = quic.clone();
        let dead_conn2 = dead_conn.clone();
        let watcher = tokio::spawn(async move {
            log::error!("DoQ Watcher: {}", q2.closed().await);
            *(dead_conn2.lock().await) = true;
        });

        let mut dns_query = [0u8; 514];
        loop {
            let dead = dead_conn.clone();

            if tank.is_some() {
                match quic.open_bi().await {
                    Ok(bistream) => {
                        let (dns_query, query_size, addr) = tank.unwrap();
                        tokio::spawn(async move {
                            let mut temp = false;
                            if let Err(e) = send_dq(
                                bistream,
                                (*dns_query, query_size),
                                addr,
                                uudp,
                                &config.overwrite,
                                config.response_timeout,
                            )
                            .await
                            {
                                log::error!("DoQ Stream: {e}");
                                temp = true;
                            }
                            if temp {
                                *(dead.lock().await) = true;
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("DoQ Connection: {e}");
                        break;
                    }
                }

                tank = None;
                continue;
            }

            let message = if let Some(dur) = config.connection_keep_alive {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(dur),
                    udp.recv_from(&mut dns_query[2..]),
                )
                .await
                {
                    Ok(message) => Some(message),
                    Err(_) => {
                        match quic.open_bi().await {
                            Ok((mut send, mut recv)) => {
                                let _ = send.write(&[]).await;
                                let _ = send.finish();
                                let _ = recv.read_chunk(1024 * 4, false).await;
                            }
                            Err(e) => {
                                log::error!("DoQ Connection: {e}");
                                *(dead.lock().await) = true;
                            }
                        };
                        None
                    }
                }
            } else {
                Some(udp.recv_from(&mut dns_query[2..]).await)
            };

            // Recive dns query
            if let Some(Ok((query_size, addr))) = message {
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
                    if let Some(close_reason) = quic.close_reason() {
                        log::error!("DoQ Connection: {close_reason}");
                    } else {
                        log::error!("DoQ Connection: Closed without reason");
                    }
                    tank = Some((Box::new(dns_query), query_size, addr));
                    watcher.abort();
                    break;
                }

                match quic.open_bi().await {
                    Ok(bistream) => {
                        tokio::spawn(async move {
                            let mut temp = false;
                            if let Err(e) = send_dq(
                                bistream,
                                (dns_query, query_size),
                                addr,
                                uudp,
                                &config.overwrite,
                                config.response_timeout,
                            )
                            .await
                            {
                                log::error!("DoQ Stream: {e}");
                                temp = true;
                            }
                            if temp {
                                *(dead.lock().await) = true;
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("DoQ Connection: {e}");
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
    udp: &'static tokio::net::UdpSocket,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
    response_timeout: u64,
) -> tokio::io::Result<()> {
    [dns_query.0[0], dns_query.0[1]] = convert_u16_to_two_u8s_be(dns_query.1 as u16);
    send.write(&dns_query.0[..dns_query.1 + 2]).await?;
    send.finish()?;

    let mut buff = [0u8; 4096];
    let mut size = 0;
    if let Some(recved) = timeout(
        std::time::Duration::from_secs(response_timeout),
        recv.read(&mut buff[size..]),
    )
    .await??
    {
        size += recved;
    } else {
        return Err(tokio::io::Error::other("closed without data"));
    }

    let message_size = convert_two_u8s_to_u16_be([buff[0], buff[1]]) as usize;
    if message_size == 0 {
        return Err(tokio::io::Error::other("malformed dns query response"));
    }

    loop {
        if size - 2 >= message_size {
            break;
        }

        match timeout(
            std::time::Duration::from_secs(response_timeout),
            recv.read(&mut buff[size..]),
        )
        .await??
        {
            Some(recved) => size += recved,
            None => return Err(tokio::io::Error::other("closed with incomplete data")),
        }
    }

    if ow.is_some() {
        crate::ipoverwrite::overwrite_ip(&mut buff[..size], ow);
    }
    let _ = udp.send_to(&buff[2..size], addr).await;
    Ok(())
}
