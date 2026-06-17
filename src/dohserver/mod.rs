mod h11p;
pub mod h2p;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, rustls};

use crate::config::DohServer;

pub async fn doh_server(dsc: &DohServer, spipe: crate::pipe::SendPipe) {
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
		if let Ok((stream, remote_addr)) = listener.accept().await
			&& let Ok(stream) = acceptor.accept(stream).await
		{
			let spipe = spipe.clone();
			tokio::spawn(stream_handler(stream, remote_addr, log_errors, spipe));
		}
	}
}

async fn stream_handler(
	mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	remote_addr: std::net::SocketAddr,
	log: bool,
	spipe: crate::pipe::SendPipe,
) {
	if let Some(alpn) = stream.get_ref().1.alpn_protocol() {
		match alpn {
			b"h2" => {
				if let Err(e) = h2p::serve_h2(&mut stream, log, spipe).await
					&& log
				{
					log::warn!("H2 <{remote_addr}>: {e}");
				}
			}
			b"http/1.1" => {
				if let Err(e) = h11p::serve_http11(&mut stream, spipe).await
					&& log
				{
					log::warn!("HTTP/1.1 <{remote_addr}>: {e}");
				}
			}
			_ => {
				log::warn!("invalid TLS ALPN");
			}
		}
	} else if let Err(e) = h11p::serve_http11(&mut stream, spipe).await
		&& log
	{
		log::warn!("HTTP/1.1 <{remote_addr}>: {e}");
	}

	stream.get_mut().1.send_close_notify();
	let _ = stream.get_mut().0.shutdown().await;
}
