use std::sync::Arc;

pub fn client(server_name: String, alpn: Vec<Vec<u8>>) -> Result<rustls::ClientConnection, rustls::Error> {
    // Generate Certificate Store for TLS
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Generate Config for TLS
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Add ALPN to TLS Config
    config.alpn_protocols = alpn;

    // Add Server Name
    let example_com = (server_name).try_into().expect("Invalid server name");
    rustls::ClientConnection::new(Arc::new(config), example_com)
}
