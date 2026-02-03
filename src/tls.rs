use std::{fmt::Debug, sync::Arc};

use crate::interface::tcp_connect_handle;

pub fn tlsconf(alpn: Vec<Vec<u8>>, dcv: bool) -> std::sync::Arc<tokio_rustls::rustls::ClientConfig> {
	let root_store = tokio_rustls::rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	let mut config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(root_store)
		.with_no_client_auth();
	config.alpn_protocols = alpn;
	config.enable_early_data = false;

	if dcv {
		config
			.dangerous()
			.set_certificate_verifier(Arc::new(NoCertificateVerification));
	}

	std::sync::Arc::new(config)
}

pub fn tlsfragmenting(
	fragmenting: &crate::config::Fragmenting,
	tls: &mut tokio_rustls::rustls::ClientConnection,
	tcp: &mut tokio::net::TcpStream,
) {
	if fragmenting.enable {
		tokio::task::block_in_place(|| {
			tokio::runtime::Handle::current().block_on(async {
				if let Err(e) = match fragmenting.method {
					crate::config::FragMethod::random => {
						crate::fragment::fragment_client_hello_rand(tls, tcp, fragmenting).await
					}
					crate::config::FragMethod::single => {
						crate::fragment::fragment_client_hello_pack(tls, tcp, fragmenting).await
					}
				} {
					log::warn!("TLS fragmenting: {e}");
				}
			});
		});
	}
}

pub trait AsyncIO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Debug + Send {}
impl AsyncIO for tokio_rustls::client::TlsStream<tokio::net::TcpStream> {}
#[cfg(feature = "nativetls")]
impl AsyncIO for tokio_native_tls::TlsStream<tokio::net::TcpStream> {}

#[cfg(feature = "nativetls")]
pub async fn dynamic_tls_conn_gen(
	alpn: &[&str],
	ctls: Arc<tokio_rustls::rustls::ClientConfig>,
) -> tokio::io::Result<Box<dyn AsyncIO>> {
	let config = &crate::CONFIG;
	if config.native_tls {
		let sni = if config.ip_as_sni {
			config.remote_addrs.ip().to_string()
		} else {
			config.server_name.clone()
		};

		Ok(Box::new(
			tokio_native_tls::TlsConnector::from(
				native_tls::TlsConnector::builder()
					.request_alpns(alpn)
					.danger_accept_invalid_certs(config.disable_certificate_validation)
					.build()
					.map_err(tokio::io::Error::other)?,
			)
			.connect(
				&sni,
				tcp_connect_handle(
					config.remote_addrs,
					config.connection,
					&config.interface,
					&config.tcp_socket_options,
				)
				.await,
			)
			.await
			.map_err(tokio::io::Error::other)?,
		))
	} else {
		let example_com = if config.ip_as_sni {
			(config.remote_addrs.ip()).into()
		} else {
			(config.server_name.clone()).try_into().expect("invalid server name")
		};

		Ok(Box::new(
			tokio_rustls::TlsConnector::from(ctls)
				.connect_with(
					example_com,
					tcp_connect_handle(
						config.remote_addrs,
						config.connection,
						&config.interface,
						&config.tcp_socket_options,
					)
					.await,
					|tls, tcp| {
						// Do fragmenting
						tlsfragmenting(&config.fragmenting, tls, tcp);
					},
				)
				.await?,
		))
	}
}

#[cfg(not(feature = "nativetls"))]
pub async fn dynamic_tls_conn_gen(
	_alpn: &[&str],
	ctls: Arc<tokio_rustls::rustls::ClientConfig>,
) -> tokio::io::Result<Box<dyn AsyncIO>> {
	let config = &crate::CONFIG;
	if config.native_tls {
		log::error!("native tls feature not available. fallback to rustls");
	}

	let example_com = if config.ip_as_sni {
		(config.remote_addrs.ip()).into()
	} else {
		(config.server_name.clone()).try_into().expect("invalid server name")
	};

	Ok(Box::new(
		tokio_rustls::TlsConnector::from(ctls)
			.connect_with(
				example_com,
				tcp_connect_handle(
					config.remote_addrs,
					config.connection,
					&config.interface,
					&config.tcp_socket_options,
				)
				.await,
				|tls, tcp| {
					// Do fragmenting
					tlsfragmenting(&config.fragmenting, tls, tcp);
				},
			)
			.await?,
	))
}

#[derive(Debug)]
struct NoCertificateVerification;

#[allow(unused_variables)]
impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
	fn verify_server_cert(
		&self,
		end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
		intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
		server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
		ocsp_response: &[u8],
		now: tokio_rustls::rustls::pki_types::UnixTime,
	) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
		Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
	}
	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
		dss: &tokio_rustls::rustls::DigitallySignedStruct,
	) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
		Err(tokio_rustls::rustls::Error::General("tls1.2 not supported".to_string()))
	}
	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
		dss: &tokio_rustls::rustls::DigitallySignedStruct,
	) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
		Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
	}
	fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
		vec![
			tokio_rustls::rustls::SignatureScheme::ML_DSA_87,
			tokio_rustls::rustls::SignatureScheme::ML_DSA_65,
			tokio_rustls::rustls::SignatureScheme::ML_DSA_44,
			tokio_rustls::rustls::SignatureScheme::ED448,
			tokio_rustls::rustls::SignatureScheme::ED25519,
			tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
			tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
			tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
			tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
			tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
			tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
			tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
			tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
			tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
		]
	}
}
