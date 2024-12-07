#[cfg(test)]
mod h11 {
    use std::{io::{Read, Write}, sync::Arc};

    use quinn::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::ServerName;

    #[test]
    fn get() {
        let mut root_store = tokio_rustls::rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let cert = tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter("cert.crt").unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        root_store.add(cert.first().unwrap().clone()).unwrap();
        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec!["http/1.1".into()];
        config.enable_early_data = true;

        let server_name = ServerName::try_from("127.0.0.1")
        .expect("invalid DNS name")
        .to_owned();
        let mut conn = tokio_rustls::rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = std::net::TcpStream::connect("127.0.0.1:443").unwrap();

        let mut stream = tokio_rustls::rustls::Stream::new(&mut conn, &mut sock);

        stream.flush().unwrap();

        stream.write(
            b"GET /?dns=PhcBAAABAAAAAAAABnZvcnRleARkYXRhCW1pY3Jvc29mdANjb20AAAEAAQ HTTP/1.1\r\n\r\n"
        ).unwrap();

        let mut buff = [0;8196];
        let size = stream.read(&mut buff).unwrap();
        println!("{:?}", String::from_utf8_lossy(&buff[..size]))
    }

    #[test]
    fn post_two_segment() {
        let mut root_store = tokio_rustls::rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let cert = tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter("cert.crt").unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        root_store.add(cert.first().unwrap().clone()).unwrap();
        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec!["http/1.1".into()];
        config.enable_early_data = true;

        let server_name = ServerName::try_from("127.0.0.1")
        .expect("invalid DNS name")
        .to_owned();
        let mut conn = tokio_rustls::rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = std::net::TcpStream::connect("127.0.0.1:443").unwrap();

        let mut stream = tokio_rustls::rustls::Stream::new(&mut conn, &mut sock);

        stream.flush().unwrap();

        let dns = std::fs::read("dns.sample").unwrap();
        stream.write(
            format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", dns.len()).as_bytes()
        ).unwrap();
        stream.write(
            dns.as_slice()
        ).unwrap();

        let mut buff = [0;8196];
        let size = stream.read(&mut buff).unwrap();
        println!("{:?}", String::from_utf8_lossy(&buff[..size]))
    }

    #[test]
    fn post_one_segment() {
        let mut root_store = tokio_rustls::rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let cert = tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter("cert.crt").unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        root_store.add(cert.first().unwrap().clone()).unwrap();
        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec!["http/1.1".into()];
        config.enable_early_data = true;

        let server_name = ServerName::try_from("127.0.0.1")
        .expect("invalid DNS name")
        .to_owned();
        let mut conn = tokio_rustls::rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = std::net::TcpStream::connect("127.0.0.1:443").unwrap();

        let mut stream = tokio_rustls::rustls::Stream::new(&mut conn, &mut sock);

        stream.flush().unwrap();

        let mut temp = [0u8; 1024];
        let dns = std::fs::read("dns.sample").unwrap();
        let head = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", dns.len());

        temp[..head.len()].copy_from_slice(head.as_bytes());
        temp[head.len()..head.len()+dns.len()].copy_from_slice(&dns);

        stream.write(
            &temp[..head.len()+dns.len()]
        ).unwrap();

        let mut buff = [0;8196];
        let size = stream.read(&mut buff).unwrap();
        println!("{:?}", String::from_utf8_lossy(&buff[..size]))
    }
}