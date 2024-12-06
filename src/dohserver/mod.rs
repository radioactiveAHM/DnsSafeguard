mod h11p;
mod h2p;

use core::str;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_rustls::{rustls, TlsAcceptor};

use crate::config::DohServer;

pub struct Tc {
    pub acceptor: TlsAcceptor,
    pub stream: (tokio::net::TcpStream, std::net::SocketAddr),
}
impl Tc {
    pub fn new(
        acceptor: TlsAcceptor,
        stream: Result<(tokio::net::TcpStream, std::net::SocketAddr), std::io::Error>,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            acceptor,
            stream: stream?,
        })
    }
    pub async fn accept(
        self,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error> {
        self.acceptor.accept(self.stream.0).await
    }
}

pub struct DnsQuery([u8; 512], usize);
impl DnsQuery {
    pub fn new(bs4dns: &[u8]) -> Result<Self, base64_url::base64::DecodeSliceError> {
        let mut buff = [0; 512];
        match base64_url::decode_to_slice(bs4dns, &mut buff) {
            Ok(b) => {
                let mut dq = Self([0; 512], b.len());
                dq.0[..b.len()].clone_from_slice(b);
                Ok(dq)
            }
            Err(e) => Err(e),
        }
    }
    pub fn value(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

pub async fn doh_server(dsc: DohServer, udp_socket_addrs: SocketAddr) {
    sleep(Duration::from_secs(2)).await;
    let certs = CertificateDer::pem_file_iter(dsc.certificate)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(dsc.key).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.send_tls13_tickets = 0;
    config.alpn_protocols = dsc.alpn.iter().map(|string| string.as_bytes().to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(dsc.listen_address).await.unwrap();

    println!("DoH server Listening on {}", dsc.listen_address);

    loop {
        match Tc::new(acceptor.clone(), listener.accept().await) {
            Ok(tc) => {
                tokio::spawn(async move {
                    if let Err(e) = tc_handler(tc, udp_socket_addrs, dsc.log_errors).await {
                        if dsc.log_errors {
                            println!("DoH server<TLS>: {e}")
                        }
                    }
                });
            }
            Err(e) => {
                if dsc.log_errors {
                    println!("DoH server<TLS>: {e}")
                }
            }
        }
    }
}

async fn tc_handler(
    tc: Tc,
    udp_socket_addrs: SocketAddr,
    log: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = tc.accept().await?;

    if let Some(alpn) = stream.get_ref().1.alpn_protocol() {
        match str::from_utf8(alpn)? {
            "h2" => h2p::serve_h2(stream, udp_socket_addrs).await?,
            "http/1.1" => h11p::serve_http11(stream, udp_socket_addrs, log).await?,
            _ => {
                stream.get_mut().1.send_close_notify();
                return Err(Box::new(rustls::Error::NoApplicationProtocol));
            }
        }
    } else {
        h11p::serve_http11(stream, udp_socket_addrs, log).await?
    }

    Ok(())
}
