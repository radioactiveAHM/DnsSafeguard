use std::{net::SocketAddr, sync::Arc};

use crate::{config, utils::tcp_connect_handle};

pub fn tlsconf(alpn: Vec<Vec<u8>>) -> std::sync::Arc<tokio_rustls::rustls::ClientConfig> {
    let root_store = tokio_rustls::rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    let mut config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    config.enable_early_data = true;

    std::sync::Arc::new(config)
}

pub fn tlsfragmenting(
    fragmenting: &crate::config::Fragmenting,
    tls: &mut quinn::rustls::ClientConnection,
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
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
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
