pub mod qtls;
pub mod transporter;
mod noise;

use std::{
    borrow::BorrowMut,
    future,
    io::Read,
    net::SocketAddr,
    str::FromStr,
    sync::Arc
};

use tokio::{sync::Mutex, time::{sleep, timeout}};

use bytes::Buf;
use h3::client::SendRequest;

use crate::config::Noise;

async fn client_noise(addr: SocketAddr, target: SocketAddr, noise: Noise)->quinn::Endpoint{
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap();
    socket.bind(&addr.into()).unwrap();

    // send noises
    noise::noiser(noise, target, &socket).await;

    let runtime = quinn::default_runtime()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no async runtime found")).unwrap();
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        runtime.wrap_udp_socket(socket.into()).unwrap(),
        runtime,
    ).unwrap()
}

pub async fn http3(server_name: String, socket_addrs: &str, udp_socket_addrs: &str, quic_conf_file: crate::config::Quic, noise: Noise, connecting_timeout_sec: u64) {
    let socketddrs = SocketAddr::from_str(socket_addrs).unwrap();

    let qaddress = {
        if socketddrs.is_ipv4() {
            SocketAddr::from_str("0.0.0.0:0").unwrap()
        }else if socketddrs.is_ipv6() {
            SocketAddr::from_str("[::]:0").unwrap()
        } else {
            panic!()
        }
    };
    // UDP socket as endpoint for quic
    let mut endpoint = {
        if noise.enable {
            client_noise(qaddress, socketddrs, noise).await
        }else {
            quinn::Endpoint::client(qaddress).unwrap()
        }
    };
    // Setup QUIC connection (QUIC Config)
    endpoint.set_default_client_config(quinn::ClientConfig::new(qtls::qtls("h3")).transport_config(transporter::tc(quic_conf_file)).to_owned());

    let mut retry = 0u8;
    loop {
        if retry==5{
            println!("Max retry reached. Sleeping for 1Min");
            sleep(std::time::Duration::from_secs(60)).await;
            retry=0;
            continue;
        }

        println!("QUIC Connecting");
        // Connect to dns server
        let connecting = endpoint.connect(socketddrs, server_name.as_str()).unwrap();

        let conn = {
            let timing = timeout(std::time::Duration::from_secs(connecting_timeout_sec), async{
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
            }).await;

            if let Ok(pending) = timing {
                pending
            } else {
                println!("Connecting timeout");
                retry += 1;
                continue;
            }
        };

        if conn.is_err(){
            println!("{}",conn.unwrap_err());
            retry+=1;
            sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // QUIC Connection Established
        retry=0;

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
            let mut dns_query = [0u8; 512];
            let udp = arc_udp.clone();

            if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
                let dq = dns_query[..query_size].to_owned();
                let h3 = h3.clone();
                let sn = server_name.clone();
                tokio::spawn(async move {
                    let h3_stat = send_request(sn, h3, dq, addr, udp).await;
                    if let Err(e) = h3_stat {
                        // Handle what to do if diffrent errors
                        let e_str = e.to_string();
                        if &e_str == "timeout" || &e_str == "read zero" {
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
            let mut buff = [0; 512];
            let body_len = body.reader().read(&mut buff).unwrap_or(0);
            // early drop
            if body_len == 0 {
                return Err(Box::new(tokio::io::Error::new(tokio::io::ErrorKind::ConnectionAborted, "read zero")));
            }

            let _ = udp.send_to(&buff[..body_len], addr).await;
        }
    }
    Ok(())
}
