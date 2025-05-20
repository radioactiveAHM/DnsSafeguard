pub fn qtls(alpn: &str) -> std::sync::Arc<quinn::crypto::rustls::QuicClientConfig> {
    let mut client_crypto = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(tokio_rustls::rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![Vec::from(alpn.as_bytes())];
    client_crypto.enable_early_data = true;

    std::sync::Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap())
}
