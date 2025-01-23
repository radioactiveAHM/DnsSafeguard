use std::{net::SocketAddr, sync::Arc};

use crate::{config, utils::tcp_connect_handle};

pub fn tlsconf(
    alpn: Vec<Vec<u8>>,
    dcv: bool,
) -> std::sync::Arc<tokio_rustls::rustls::ClientConfig> {
    let root_store = tokio_rustls::rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    let mut config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    config.enable_early_data = true;

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
                    crate::config::FragMethod::linear => {
                        crate::fragment::fragment_client_hello(tls, tcp, fragmenting).await
                    }
                    crate::config::FragMethod::random => {
                        crate::fragment::fragment_client_hello_rand(tls, tcp, fragmenting).await
                    }
                    crate::config::FragMethod::single => {
                        crate::fragment::fragment_client_hello_pack(tls, tcp).await
                    }
                    crate::config::FragMethod::jump => {
                        crate::fragment::fragment_client_hello_jump(tls, tcp, fragmenting).await
                    }
                } {
                    println!("TLS Fragmenting: {e}");
                }
            });
        });
    }
}

pub async fn tls_conn_gen(
    server_name: String,
    disable_domain_sni: bool,
    socket_addrs: SocketAddr,
    fragmenting: config::Fragmenting,
    ctls: Arc<tokio_rustls::rustls::ClientConfig>,
    connection_cfg: config::Connection,
) -> tokio::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let example_com = if disable_domain_sni {
        (socket_addrs.ip()).into()
    } else {
        (server_name).try_into().expect("Invalid server name")
    };

    tokio_rustls::TlsConnector::from(ctls)
        .connect_with_stream(
            example_com,
            tcp_connect_handle(socket_addrs, connection_cfg).await,
            |tls, tcp| {
                // Do fragmenting
                if fragmenting.enable {
                    tokio::task::block_in_place(|| {
                        tlsfragmenting(&fragmenting, tls, tcp);
                    });
                }
            },
        )
        .await
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
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
            tokio_rustls::rustls::SignatureScheme::ED448,
        ]
    }
}
