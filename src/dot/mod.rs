use rand::Rng;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::rule::rulecheck;
use crate::utils::{convert_two_u8s_to_u16_be, unsafe_staticref};
use crate::{tls, utils::convert_u16_to_two_u8s_be};

enum IdType {
    ZeroID(std::net::SocketAddr),
    WithID(std::net::SocketAddr),
}

pub async fn dot(
    config: &'static crate::config::Config,
    rules: &'static Option<Vec<crate::rule::Rule>>,
) {
    let udp = crate::udp::udp_socket(config.serve_addrs).await.unwrap();
    let uudp = unsafe_staticref(&udp);
    let ctls = tls::tlsconf(vec![b"dot".to_vec()], config.disable_certificate_validation);
    loop {
        println!("DOT Connecting");
        let tls = crate::tls::dynamic_tls_conn_gen(
            config.native_tls,
            config.server_name.to_string(),
            &["dot"],
            config.disable_certificate_validation,
            config.ip_as_sni,
            config.remote_addrs,
            config.fragmenting.clone(),
            ctls.clone(),
            config.connection,
            &config.interface,
        )
        .await;
        if tls.is_err() {
            println!("{}", tls.unwrap_err());
            tokio::time::sleep(std::time::Duration::from_secs(
                config.connection.reconnect_sleep,
            ))
            .await;
            continue;
        }
        println!("DOT Connection Established");

        let (r, w) = tokio::io::split(tls.unwrap());

        // Hold dns message ID with it's dns resolver Addr to match
        let waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        let waiters2 = waiters.clone();

        tokio::select! {
            recver = tokio::spawn(async move { recv_query(uudp, r, waiters2, &config.overwrite).await }) => {
                if let Err(e) = recver {
                    println!("DoT: {e}")
                }
            }
            sender = send_query(uudp, rules, w, waiters) => {
                if let Err(e) = sender {
                    println!("DoT: {e}")
                }
            }
        }
    }
}

async fn recv_query<R: tokio::io::AsyncRead + Unpin>(
    udp: &'static tokio::net::UdpSocket,
    mut r: R,
    waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>>,
    ow: &'static Option<Vec<crate::ipoverwrite::IpOverwrite>>,
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
                if ow.is_some() {
                    crate::ipoverwrite::overwrite_ip(message, ow);
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
    udp: &'static tokio::net::UdpSocket,
    rules: &Option<Vec<crate::rule::Rule>>,
    mut w: W,
    waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>>,
) -> tokio::io::Result<()> {
    let mut query = [0; 514];
    loop {
        let (size, addr) = udp.recv_from(&mut query[2..]).await?;
        if (rules.is_some()
            && rulecheck(rules, crate::rule::RuleDqt::Tls(query, size), addr, udp).await)
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
