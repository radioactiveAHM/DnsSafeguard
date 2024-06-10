use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;

pub fn qtls(alpn: &str) -> Arc<QuicClientConfig> {
    let alpn: &[&[u8]] = &[alpn.as_bytes()];

    let root_store = tokio_rustls::rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );

    let mut client_crypto = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = alpn.iter().map(|&x| x.into()).collect();
    client_crypto.enable_early_data = true;

    Arc::new(QuicClientConfig::try_from(client_crypto).unwrap())
}
