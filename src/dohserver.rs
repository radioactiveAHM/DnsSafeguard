use std::net::SocketAddr;
use std::sync::Arc;
use bytes::Bytes;
use h2::server::SendResponse;
use h2::Reason;
use http::Response;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::{rustls, TlsAcceptor};

use crate::config::DohServer;

struct Tc {
    acceptor: TlsAcceptor,
    stream: (tokio::net::TcpStream, std::net::SocketAddr)
}
impl Tc {
    fn new(acceptor: TlsAcceptor, stream: Result<(tokio::net::TcpStream, std::net::SocketAddr), std::io::Error>) -> Result<Self, std::io::Error> {
        Ok(
            Self {
                acceptor,
                stream: stream?
            }
        )
    }
}

struct DnsQuery ([u8;512], usize);
impl DnsQuery {
    fn new(bs4dns: &[u8])->Result<Self, base64_url::base64::DecodeSliceError>{
        let mut buff = [0;512];
        match base64_url::decode_to_slice(bs4dns, &mut buff) {
            Ok(b)=>{
                let mut dq = Self([0;512], b.len());
                dq.0[..b.len()].clone_from_slice(b);
                Ok(dq)
            },
            Err(e)=>{
                Err(dbg!(e))
            }
        }
        
    }
}

pub async fn doh_server(dsc: DohServer, udp_socket_addrs: SocketAddr){
    let certs = CertificateDer::pem_file_iter(dsc.certificate).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = PrivateKeyDer::from_pem_file(dsc.key).unwrap();
    let mut config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key).unwrap();
    config.alpn_protocols = vec![b"h2".into()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(dsc.listen_address).await.unwrap();

    println!("DoH server Listening on {}", dsc.listen_address);

    loop {
        match Tc::new(acceptor.clone(), listener.accept().await) {
            Ok(tc)=>{
                tokio::spawn(async move {
                    if let Err(e) = tc_handler(tc, dsc.stream_timeout, udp_socket_addrs).await{
                        println!("{e}")
                    }
                });
            },
            Err(e)=>{
                println!("{e}");
            }
        }
    }
}

async fn tc_handler(tc: Tc, timeout_sec: u64, udp_socket_addrs: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let stream = tc.acceptor.accept(tc.stream.0).await?;
    let mut conn= h2::server::handshake(stream).await?;
    
    let mut deadloop: u8 = 0;
    loop {
        if deadloop == 20 {
            // dead tcp connection
            break;
        }
        if timeout(std::time::Duration::from_secs(timeout_sec), async {
            if let Some(Ok((req, mut resp))) = conn.accept().await {
                deadloop = 0;
                if let Some(bs4dns) = req.uri().query(){
                    if let Ok(dq)=DnsQuery::new(&bs4dns.as_bytes()[4..]){
                        tokio::spawn(async move {
                            if let Err(e)= handle_dns_req(&mut resp, dq, udp_socket_addrs).await{
                                resp.send_reset(Reason::INTERNAL_ERROR);
                                println!("{e}");
                            }
                        });
                    }
                }
            } else {
                deadloop += 1;
            }
        }).await.is_err() {
            conn.abrupt_shutdown(Reason::SETTINGS_TIMEOUT);
            break;
        }
    }

    Ok(())
}

async fn handle_dns_req(resp: &mut SendResponse<Bytes>, dq: DnsQuery, udp_socket_addrs: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;
    agent.send(&dq.0[..dq.1]).await?;


    let mut buff = [0; 512];
    let size = agent.recv(&mut buff).await?;

    if size>5{
        let rto = timeout(std::time::Duration::from_secs(5), async {
            handle_resp(resp, &buff, size).await
        }).await;
        
        if let Ok(inside) = rto {
            inside?;
        } else {
            resp.send_reset(Reason::SETTINGS_TIMEOUT);
        }
    }else {
        resp.send_reset(Reason::INTERNAL_ERROR);
    }

    Ok(())
}

async fn handle_resp(resp: &mut SendResponse<Bytes>, buff: &[u8], size: usize) -> Result<(), Box<dyn std::error::Error>> {
    let dq_resp = Bytes::copy_from_slice(&buff[..size]);
    resp.send_response(
        Response::builder().status(200).header("Content-Type", "application/dns-message")
        .header("content-length", size)
        .body(())?,
        false
    )?
    .send_data(dq_resp, true)?;

    Ok(())
}