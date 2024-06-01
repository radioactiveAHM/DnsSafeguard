mod qtls;

use std::{
    borrow::BorrowMut, future, io::Read, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr, sync::Arc, time::Duration
};

use tokio::sync::Mutex;

use bytes::Buf;
use h3::client::SendRequest;

pub async fn doh3(server_name: String, socket_addrs: &str, udp_socket_addrs: &str) {
    // UDP socket as endpoint for quic
    let mut endpoint = quinn::Endpoint::client(std::net::SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from_str("0.0.0.0").unwrap(),
        5432,
    )))
    .unwrap();
    loop {        
        println!("New QUIC connection");
    
        endpoint.set_default_client_config(qtls::qtls());
        // Connect to dns server
        let conn = endpoint
            .connect(
                std::net::SocketAddr::V4(SocketAddrV4::from_str(socket_addrs).unwrap()),
                server_name.as_str(),
            )
            .unwrap()
            .await
            .expect("Failed to connect to server");
    
        println!("Connection Established");
    
        let quic = h3_quinn::Connection::new(conn);
    
        // HTTP/3 Client
        let (mut driver, h3) = h3::client::new(quic).await.unwrap();
        let drive = async move {
            future::poll_fn(|cx| driver.poll_close(cx)).await?;
            Ok::<(), Box<dyn std::error::Error + Send>>(())
        };
    
        tokio::spawn(drive);
    
        // UDP socket to listen for DNS query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();
        let m_udp = Mutex::new(h3);

        // prepare for atomic
        let am_h3 = Arc::new(m_udp);
        let am_udp = Arc::new(Mutex::new(udp));
    
        loop {
            // TODO: Handle quic closed connection
            // TODO: Handle Errors
            let mut timeout = Duration::from_millis(30);
            // if only one udp bing used means no h3 task running so go for longer timeout
            if dbg!(Arc::strong_count(&am_udp))==1{
                timeout = Duration::from_secs(5);
            }
            // Recive dns query
            let mut dns_query: [u8; 8196] = [0u8; 8196];
            let udp = am_udp.clone();
            let locked_udp = udp.lock().await;

            let udp_ok = tokio::time::timeout(timeout, async {
                locked_udp.recv_from(&mut dns_query).await
            }).await;
            // Drop udp to unlock
            drop(locked_udp);
            dbg!("incoming");
            if udp_ok.is_err() {
                continue;
            }

            if let Ok((query_size, addr)) = udp_ok.unwrap(){
                let dq = &dns_query[..query_size];
                
                let h3 = am_h3.clone();
                tokio::spawn(send_request(server_name.clone(),h3, dq.to_owned(),addr,udp));
            }
        }
    }
}

async fn send_request(
    server_name: String,
    h3: Arc<Mutex<SendRequest<h3_quinn::OpenStreams, bytes::Bytes>>>,
    dns_query: Vec<u8>,
    addr: SocketAddr,
    udp: Arc<Mutex<tokio::net::UdpSocket>>
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let query_base64url = base64_url::encode(&dns_query);

    let req = http::Request::get(format!(
        "https://{}/dns-query?dns={}",
        server_name, query_base64url
    ))
    .header("Accept", "application/dns-message")
    .body(()).unwrap();

    // Send HTTP request
    let mut h3_locked = h3.lock().await;
    let mut reqs = h3_locked.borrow_mut().send_request(req).await?;
    reqs.finish().await?;

    // HTTP respones
    let resp = reqs.recv_response().await?;
    dbg!(resp.status());

    if resp.status() == http::status::StatusCode::OK {
        // get body
        if let Some(body) = reqs.recv_data().await? {
            let mut buff = [0; 8196];
            let body_len = body.reader().read(&mut buff).unwrap_or(0);
            // early drop
            drop(reqs); drop(h3_locked);
            if body_len==0{
                return Ok(());
            }
            println!("waiting to lock udp");
            if udp.lock().await.send_to(&buff[..body_len], addr).await.is_err(){
                return Ok(());
            };
        }
    }
    println!("finished the job");
    Ok(())
}
