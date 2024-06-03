use std::sync::Arc;

pub fn h2tls() -> tokio_rustls::TlsConnector {
    let root_store =
        tokio_rustls::rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    tokio_rustls::TlsConnector::from(Arc::new(config))
}