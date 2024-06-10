pub mod qtls;
pub mod transporter;

use std::{
    borrow::BorrowMut,
    future,
    io::Read,
    net::SocketAddr,
    str::FromStr,
    sync::Arc
};

use rand::Rng;
use tokio::sync::Mutex;

use bytes::Buf;
use h3::client::SendRequest;

pub async fn http3(server_name: String, socket_addrs: &str, udp_socket_addrs: &str, quic_conf_file: crate::config::Quic) {
    let qaddress = {
        let mut mr_randy = rand::rngs::OsRng;
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
    endpoint.set_default_client_config(quinn::ClientConfig::new(qtls::qtls("h3")).transport_config(transporter::tc(quic_conf_file)).to_owned());
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
                let conn = endpoint.connect(SocketAddr::from_str(socket_addrs).unwrap(), server_name.as_str()).unwrap().await;
                if conn.is_ok(){
                    println!("QUIC Connection Established");
                }
                conn
            }
        };

        if conn.is_err(){
            println!("Failed to Established QUIC Connection");
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
        // prepare for atomic
        let arc_udp = Arc::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());
        let dead_conn = Arc::new(Mutex::new(false));

        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            let quic_conn_dead = dead_conn.clone();
            if *quic_conn_dead.lock().await {
                break;
            }

            // Recive dns query
            let mut dns_query = [0u8; 768];
            let udp = arc_udp.clone();

            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
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
            }else {
                println!("Failed to recv DNS Query");
            }
        }
    }
}

async fn send_request(
    server_name: String,
    mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    dns_query: Vec<u8>,
    addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
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
    let resp: http::Response<()> = reqs.recv_response().await?;

    if resp.status() == http::status::StatusCode::OK {
        // get body
        if let Some(body) = reqs.recv_data().await? {
            let mut buff = [0; 768];
            let body_len = body.reader().read(&mut buff).unwrap_or(0);
            // early drop
            if body_len == 0 {
                return Ok(());
            }
            if udp
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
