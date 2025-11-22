mod h11p;
pub mod h2p;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, rustls};

use crate::config::DohServer;

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
	pub async fn accept(self) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, tokio::io::Error> {
		self.acceptor.accept(self.stream.0).await
	}
}

pub async fn doh_server(dsc: &DohServer, serve_addrs: SocketAddr) {
	sleep(Duration::from_secs(2)).await;
	let certs = CertificateDer::pem_file_iter(&dsc.certificate)
		.unwrap()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();
	let key = PrivateKeyDer::from_pem_file(&dsc.key).unwrap();
	let mut config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.unwrap();
	config.alpn_protocols = dsc.alpn.iter().map(|string| string.as_bytes().to_vec()).collect();
	let acceptor = TlsAcceptor::from(Arc::new(config));

	let listener = tokio::net::TcpListener::bind(dsc.listen_address).await.unwrap();

	log::info!("listening on {}", dsc.listen_address);

	let log_errors = dsc.log_errors;

	loop {
		match Tc::new(acceptor.clone(), listener.accept().await) {
			Ok(tc) => {
				tokio::spawn(tc_handler(tc, serve_addrs, log_errors));
			}
			Err(e) => {
				if dsc.log_errors {
					log::warn!("{e}");
				}
			}
		}
	}
}

async fn tc_handler(tc: Tc, serve_addrs: SocketAddr, log: bool) {
	let mut tls = match tc.accept().await {
		Ok(tls) => tls,
		Err(e) => {
			log::warn!("TLS: {e}");
			return;
		}
	};

	if let Some(alpn) = tls.get_ref().1.alpn_protocol() {
		match alpn {
			b"h2" => {
				if let Err(e) = h2p::serve_h2(&mut tls, serve_addrs, log).await
					&& log
				{
					log::warn!("H2: {e}");
				}
			}
			b"http/1.1" => {
				if let Err(e) = h11p::serve_http11(&mut tls, serve_addrs).await
					&& log
				{
					log::warn!("HTTP/1.1: {e}");
				}
			}
			_ => {
				log::warn!("invalid TLS ALPN");
			}
		}
	} else if let Err(e) = h11p::serve_http11(&mut tls, serve_addrs).await
		&& log
	{
		log::warn!("HTTP/1.1: {e}");
	}

	tls.get_mut().1.send_close_notify();
	let _ = tls.get_mut().0.shutdown().await;
}
