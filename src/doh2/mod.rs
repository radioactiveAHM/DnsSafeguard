use h2::client::SendRequest;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio:: sync::Mutex;
use crate::fragment;

use crate::config;
use crate::tls;

pub async fn http2(server_name: String, socket_addrs: &str, udp_socket_addrs: &str, fragmenting: &config::Fragmenting) {
    // TLS Conf
    let h2tls = tls::tlsconf(vec![b"h2".to_vec()]);
    let mut tls_retry = 0u8;
    loop {
        if tls_retry == 5 {
            println!("Cannot establish tls connection");
            panic!();
        }
        // TCP Connection
        // Panic if socket_addrs invalid
        let tcp = tokio::net::TcpStream::connect(socket_addrs).await.unwrap();
        println!("New H2 connection");
        
        let example_com = (server_name.clone())
        .try_into()
        .expect("Invalid server name");
        // TLS Client
        let tls_conn = tokio_rustls::TlsConnector::from(Arc::clone(&h2tls)).connect_with_stream(example_com, tcp, |tls, tcp| {
            // Do fragmenting
            if fragmenting.enable{
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        match fragmenting.method.as_str(){
                            "linear" => fragment::fragment_client_hello(tls, tcp).await,
                            "random" => fragment::fragment_client_hello_rand(tls, tcp).await,
                            "single" => fragment::fragment_client_hello_pack(tls, tcp).await,
                            _ => panic!("Invalid fragment method"),
                        }
                    });
                });
            }
        }).await;
        if tls_conn.is_err() {
            println!("TLS handshake failed. Retry {}", tls_retry);
            tls_retry = tls_retry + 1;
            continue;
        }

        let (client, h2_) = h2::client::handshake(tls_conn.unwrap()).await.unwrap();
        println!("H2 Connection Established");

        // handle h2 low level connection
        tokio::spawn(async move {
            if let Err(e) = h2_.await {
                println!("GOT ERR={:?}", e);
            }
        });

        // UDP socket to listen for DNS query
        let udp = Mutex::new(tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap());

        // prepare atomic
        let arc_udp = Arc::new(udp);
        let dead_conn = Arc::new(Mutex::new(false));

        loop {
            // Check if Connection is dead
            // quic_conn_dead will be passed to task if connection alive
            {
                let h2_conn_dead = dead_conn.clone();
                if *h2_conn_dead.lock().await {
                    break;
                }
            }

            // Set timeout for udp
            let mut timeout = Duration::from_millis(30);
            // if only one udp bing used means no h2 task running so go for longer timeout
            if Arc::strong_count(&arc_udp) == 1 {
                timeout = Duration::from_secs(5);
            }

            // Recive dns query
            let mut dns_query = [0u8; 768];
            let udp = arc_udp.clone();
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
                // Base64url dns query
                let query_base64url = base64_url::encode(&dns_query[..query_size]);
                let h2_client = client.clone();
                let sn = server_name.clone();
                let dead_conn_arc = dead_conn.clone();
                tokio::spawn(async move {
                    let mut temp = false;
                    if let Err(e) = send_req(sn, query_base64url, h2_client, addr, udp).await {
                        let error = e.to_string();
                        println!("{}", error);
                        temp = true;
                        // for some weird reason if i try to lock dead_conn_arc here error occur
                    }
                    if temp {
                        *(dead_conn_arc.lock().await) = true;
                    }
                });
            }
        }
    }
}

async fn send_req(
    server_name: String,
    query_base64url: String,
    mut h2_client: SendRequest<bytes::Bytes>,
    addr: SocketAddr,
    udp: Arc<Mutex<tokio::net::UdpSocket>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // HTTP Request
    let req = http::Request::get(format!(
        "https://{}/dns-query?dns={}",
        server_name, query_base64url
    ))
    .header("Accept", "application/dns-message")
    .body(())?;

    // Sending request
    let resp = h2_client.send_request(req, false)?.0.await?;

    if resp.status() == http::status::StatusCode::OK {
        // Get body (dns query)
        if let Some(body) = resp.into_body().data().await {
            udp.lock().await.send_to(&body?, addr).await?;
        }
    }
    Ok(())
}
