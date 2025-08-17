use rand::Rng;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::{
    CONFIG,
    rule::rulecheck,
    tls,
    utils::{convert_two_u8s_to_u16_be, convert_u16_to_two_u8s_be},
};

enum IdType {
    ZeroID(std::net::SocketAddr),
    WithID(std::net::SocketAddr),
}

pub async fn dot(rules: std::sync::Arc<Option<Vec<crate::rule::Rule>>>) {
    let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());
    let ctls = tls::tlsconf(vec![b"dot".to_vec()], CONFIG.disable_certificate_validation);
    loop {
        log::info!("DOT Connecting");
        let tls = crate::tls::dynamic_tls_conn_gen(&["dot"], ctls.clone()).await;
        if tls.is_err() {
            log::error!("DoT: {}", tls.unwrap_err());
            tokio::time::sleep(std::time::Duration::from_secs(
                CONFIG.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        log::info!("DOT Connection Established");

        let (r, w) = tokio::io::split(tls.unwrap());

        // Hold dns message ID with it's dns resolver Addr to match
        let waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        let waiters2 = waiters.clone();
        let udp2 = udp.clone();
        tokio::select! {
            recver = tokio::spawn(async move { recv_query(udp2, r, waiters2).await }) => {
                if let Err(e) = recver {
                    log::error!("DoT: {e}")
                }
            }
            sender = send_query(udp.clone(), rules.clone(), w, waiters) => {
                if let Err(e) = sender {
                    log::error!("DoT: {e}")
                }
            }
        }
    }
}

async fn recv_query<R: tokio::io::AsyncRead + Unpin>(
    udp: Arc<tokio::net::UdpSocket>,
    mut r: R,
    waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>>,
) -> tokio::io::Result<()> {
    let mut buffer = vec![0; 1024 * 8];
    let mut size: usize = 0;
    loop {
        size += r.read(&mut buffer[size..]).await?;
        if size == 0 {
            continue;
        }
        loop {
            if size < 12 {
                break;
            }

            let message_size = convert_two_u8s_to_u16_be([buffer[0], buffer[1]]) as usize;

            if message_size < 12 {
                return Err(tokio::io::Error::other("Mailformed Dns query response"));
            }

            if size < message_size {
                break;
            }

            let message = &mut buffer[2..message_size + 2];
            let id = convert_two_u8s_to_u16_be([message[0], message[1]]);
            if let Some(addr) = waiters.lock().await.remove(&id) {
                if CONFIG.overwrite.is_some() {
                    crate::ipoverwrite::overwrite_ip(message, &CONFIG.overwrite);
                }
                match addr {
                    IdType::WithID(addr) => {
                        udp.send_to(message, addr).await?;
                    }
                    IdType::ZeroID(addr) => {
                        [message[0], message[1]] = [0, 0];
                        udp.send_to(message, addr).await?;
                    }
                }
            }
            size -= message_size + 2;
            buffer.drain(..message_size + 2);

            if size == 0 {
                buffer = vec![0; 1024 * 8];
            }
        }
    }
}

async fn send_query<W: tokio::io::AsyncWrite + Unpin + Send>(
    udp: Arc<tokio::net::UdpSocket>,
    rules: std::sync::Arc<Option<Vec<crate::rule::Rule>>>,
    mut w: W,
    waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>>,
) -> tokio::io::Result<()> {
    let mut query = [0; 514];
    loop {
        let message = if let Some(dur) = CONFIG.connection_keep_alive {
            match tokio::time::timeout(
                std::time::Duration::from_secs(dur),
                udp.recv_from(&mut query[2..]),
            )
            .await
            {
                Ok(message) => Some(message),
                Err(_) => {
                    let _ = w
                        .write(&[0, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]) // Empty dns query
                        .await?;
                    None
                }
            }
        } else {
            Some(udp.recv_from(&mut query[2..]).await)
        };

        if let Some(Ok((size, addr))) = message {
            if (rules.is_some()
                && rulecheck(
                    rules.clone(),
                    crate::rule::RuleDqt::Tls(query, size),
                    addr,
                    udp.clone(),
                )
                .await)
                || size < 12
            {
                continue;
            }
            [query[0], query[1]] = convert_u16_to_two_u8s_be(size as u16);
            let mut id = convert_two_u8s_to_u16_be([query[2], query[3]]);
            if id == 0 {
                id = rand::rng().random::<u16>();
                [query[2], query[3]] = convert_u16_to_two_u8s_be(id);
                waiters.lock().await.insert(id, IdType::ZeroID(addr));
            } else {
                waiters.lock().await.insert(id, IdType::WithID(addr));
            }
            let _ = w.write(&query[..size + 2]).await?;
        }
    }
}
