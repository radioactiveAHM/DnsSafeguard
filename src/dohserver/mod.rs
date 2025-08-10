mod h11p;
pub mod h2p;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, rustls};

use crate::config::DohServer;
use crate::utils::unsafe_staticref;

pub struct Tc {
    pub acceptor: TlsAcceptor,
    pub stream: (tokio::net::TcpStream, std::net::SocketAddr),
}
impl Tc {
    pub fn new(
        acceptor: TlsAcceptor,
        stream: Result<(tokio::net::TcpStream, std::net::SocketAddr), tokio::io::Error>,
    ) -> Result<Self, tokio::io::Error> {
        Ok(Self {
            acceptor,
            stream: stream?,
        })
    }
    pub async fn accept(
        self,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, tokio::io::Error> {
        self.acceptor.accept(self.stream.0).await
    }
}

pub struct DnsQuery([u8; 768], usize);
impl DnsQuery {
    pub fn new(bs4dns: &[u8]) -> tokio::io::Result<Self> {
        // (512*4)/3=683
        let mut buff = [0; 768];
        match base64_url::decode_to_slice(bs4dns, &mut buff) {
            Ok(b) => {
                let mut dq = Self([0; 768], b.len());
                dq.0[..b.len()].clone_from_slice(b);
                Ok(dq)
            }
            Err(e) => Err(tokio::io::Error::other(e)),
        }
    }
    pub fn value(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

pub async fn doh_server(dsc: DohServer, serve_addrs: SocketAddr) {
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
    config.alpn_protocols = dsc
        .alpn
        .iter()
        .map(|string| string.as_bytes().to_vec())
        .collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let mut tsocket = if dsc.listen_address.is_ipv4() {
        tokio::net::TcpSocket::new_v4().unwrap()
    } else {
        tokio::net::TcpSocket::new_v6().unwrap()
    };
    crate::interface::set_tcp_socket_options(&mut tsocket);
    tsocket.bind(dsc.listen_address).unwrap();
    let listener = tsocket.listen(128).unwrap();

    println!("DoH server Listening on {}", dsc.listen_address);

    let cache_control: &'static String = unsafe_staticref(&dsc.cache_control);

    loop {
        match Tc::new(acceptor.clone(), listener.accept().await) {
            Ok(tc) => {
                tokio::spawn(async move {
                    if let Err(e) = tc_handler(
                        tc,
                        serve_addrs,
                        dsc.log_errors,
                        cache_control,
                        dsc.response_timeout,
                    )
                    .await
                        && dsc.log_errors
                    {
                        println!("DoH server<TLS>: {e}")
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
    serve_addrs: SocketAddr,
    log: bool,
    cache_control: &'static String,
    response_timeout: (u64, u64),
) -> tokio::io::Result<()> {
    let mut stream = tc.accept().await?;

    if let Some(alpn) = stream.get_ref().1.alpn_protocol() {
        match alpn {
            b"h2" => {
                h2p::serve_h2(stream, serve_addrs, log, cache_control, response_timeout).await?
            }
            b"http/1.1" => {
                h11p::serve_http11(stream, serve_addrs, log, cache_control, response_timeout)
                    .await?
            }
            _ => {
                stream.get_mut().1.send_close_notify();
                return Err(tokio::io::Error::other(
                    rustls::Error::NoApplicationProtocol,
                ));
            }
        }
    } else {
        h11p::serve_http11(stream, serve_addrs, log, cache_control, response_timeout).await?
    }

    Ok(())
}
