use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;

pub fn qtls() -> quinn::ClientConfig {
    const ALPN_H3: &[&[u8]] = &[b"h3"];

    let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_H3.iter().map(|&x| x.into()).collect();

    quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()))
}
