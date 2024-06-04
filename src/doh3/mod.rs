mod qtls;
mod transporter;

use std::{
    borrow::BorrowMut,
    future,
    io::Read,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use rand::Rng;
use tokio::sync::Mutex;

use bytes::Buf;
use h3::client::SendRequest;

pub async fn http3(server_name: String, socket_addrs: &str, udp_socket_addrs: &str, quic_conf_file: crate::config::Quic) {
    let qaddress = {
        let mut mr_randy = rand::rngs::OsRng::default();
        let port = mr_randy.gen_range(4000..5000);
        if SocketAddr::from_str(socket_addrs).unwrap().is_ipv4() {
            SocketAddr::from_str(format!("0.0.0.0:{port}").as_str()).unwrap()
        }else if SocketAddr::from_str(socket_addrs).unwrap().is_ipv6() {
            SocketAddr::from_str(format!("[::]:{port}").as_str()).unwrap()
        } else {
            panic!()
        }
    };
    // UDP socket as endpoint for quic
    let mut endpoint = quinn::Endpoint::client(qaddress).unwrap();
    // Setup QUIC connection (QUIC Config)
    endpoint.set_default_client_config(quinn::ClientConfig::new(qtls::qtls()).transport_config(transporter::tc(quic_conf_file)).to_owned());
    loop {
        println!("New QUIC connection");
        // Connect to dns server
        let connecting = endpoint.connect(SocketAddr::from_str(socket_addrs).unwrap(), server_name.as_str()).unwrap();

        let conn = {
            let connecting = connecting.into_0rtt();
            if let Ok((conn, rtt)) = connecting {
                rtt.await;
                println!("QUIC 0RTT Connection Established");
                Ok(conn)
            }else {
                println!("QUIC Connection Established");
                endpoint.connect(SocketAddr::from_str(socket_addrs).unwrap(), server_name.as_str()).unwrap().await
            }
        };

        if conn.is_err(){
            continue;
        }

        // HTTP/3 Client
        let (mut driver, h3) = h3::client::new(h3_quinn::Connection::new(conn.unwrap())).await.unwrap();
        let drive = async move {
            future::poll_fn(|cx| driver.poll_close(cx)).await?;
            Ok::<(), Box<dyn std::error::Error + Send>>(())
        };

        tokio::spawn(drive);

        // UDP socket to listen for DNS query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        // prepare for atomic
        let am_udp = Arc::new(Mutex::new(udp));
        let dead_conn = Arc::new(Mutex::new(false));

        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let quic_conn_dead = dead_conn.clone();
            let quic_conn_dead_locked = quic_conn_dead.lock().await;
            if *quic_conn_dead_locked {
                break;
            }
            // Unlock
            drop(quic_conn_dead_locked);

            let mut timeout = Duration::from_millis(30);
            // if only one udp bing used means no h3 task running so go for longer timeout
            if Arc::strong_count(&am_udp) == 1 {
                timeout = Duration::from_secs(5);
            }
            // Recive dns query
            let mut dns_query: [u8; 8196] = [0u8; 8196];
            let udp = am_udp.clone();
            let locked_udp = udp.lock().await;

            let udp_ok = tokio::time::timeout(timeout, async {
                locked_udp.recv_from(&mut dns_query).await
            })
            .await;
            // Drop udp to unlock
            drop(locked_udp);
            if udp_ok.is_err() {
                continue;
            }

            if let Ok((query_size, addr)) = udp_ok.unwrap() {
                let dq = dns_query[..query_size].to_owned();
                let h3 = h3.clone();
                let sn = server_name.clone();
                tokio::spawn(async move {
                    let h3_stat = send_request(sn, h3, dq, addr, udp).await;
                    if let Err(e) = h3_stat {
                        // Handle what to do if diffrent errors
                        if e.to_string() == "timeout" {
                            *(quic_conn_dead.lock().await) = true;
                        }
                    }
                });
            }
        }
    }
}

async fn send_request(
    server_name: String,
    mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    dns_query: Vec<u8>,
    addr: SocketAddr,
    udp: Arc<Mutex<tokio::net::UdpSocket>>,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let query_base64url = base64_url::encode(&dns_query);

    let req = http::Request::get(format!(
        "https://{}/dns-query?dns={}",
        server_name, query_base64url
    ))
    .header("Accept", "application/dns-message")
    .body(())
    .unwrap();

    // Send HTTP request
    let mut reqs = h3.borrow_mut().send_request(req).await?;
    reqs.finish().await?;

    // HTTP respones
    let resp = reqs.recv_response().await?;

    if resp.status() == http::status::StatusCode::OK {
        // get body
        if let Some(body) = reqs.recv_data().await? {
            let mut buff = [0; 8196];
            let body_len = body.reader().read(&mut buff).unwrap_or(0);
            // early drop
            if body_len == 0 {
                return Ok(());
            }
            if udp
                .lock()
                .await
                .send_to(&buff[..body_len], addr)
                .await
                .is_err()
            {
                return Ok(());
            };
        }
    }
    Ok(())
}
