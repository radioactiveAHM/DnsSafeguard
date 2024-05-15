mod config;
mod fragment;

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::vec;
fn main() {
    // Load config
    // If config file does not exist or malformed, panic occurs.
    let conf = config::load_config();

    if conf.ipv6.enable{
        std::thread::spawn(move||{
            dns(conf.ipv6.server_name, &conf.ipv6.socket_addrs, &conf.ipv6.udp_socket_addrs)
        });
    }

    dns(conf.server_name, &conf.socket_addrs, &conf.udp_socket_addrs);
}

fn catch_in_buff(find: &[u8], buff: &[u8]) -> (usize, usize) {
    let size = find.len();
    let mut index = size;
    for _ in &buff[size..] {
        if find == &buff[index - size..index] {
            return (index - size, index);
        }
        index = index + 1
    }
    return (0, 0);
}

fn dns(server_name: String, socket_addrs: &str, udp_socket_addrs: &str) {
    // Main loop
    let mut frag_retry = 0;
    'main: loop {
        println!("New TLS connection");
        // Generate Certificate Store for TLS
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Generate Config for TLS
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Add ALPN to TLS Config
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let rc_config = Arc::new(config);
        // Add Server Name
        let example_com = (server_name.clone())
            .try_into()
            .expect("Invalid server name");
        let client = rustls::ClientConnection::new(rc_config, example_com);

        let mut c = client.unwrap();

        // TCP socket for TLS
        let mut tcp = std::net::TcpStream::connect(socket_addrs).unwrap_or_else(|e| {
            println!("{}", e);
            panic!();
        });

        // Perform TLS Client Hello fragmenting
        let fraged = fragment::fragment_client_hello(&mut c, &mut tcp);
        if fraged.is_err() {
            if frag_retry == 5 {
                // 5 times retried so exit
                println!("{}", fraged.unwrap_err());
                panic!();
            } else {
                // Can't send Tls client hello so retry
                frag_retry = frag_retry + 1;
                continue 'main;
            }
        }

        // Complete TLS handshake
        c.complete_io(&mut tcp).unwrap();

        // UDP socket to listen for DNS query
        let udp = UdpSocket::bind(udp_socket_addrs).unwrap_or_else(|e| {
            println!("{}", e);
            panic!();
        });

        loop {
            // dbg!("loop start");
            let mut dns_query: [u8; 8196] = [0u8; 8196];
            let udp_ok = udp.recv_from(&mut dns_query);
            if udp_ok.is_err() {
                continue;
            }
            let (query_size, addr) = udp_ok.unwrap();
            // dbg!("udp.recv_from");
            let http = format!(
                    "POST /dns-query HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-type: application/dns-message\r\nContent-length: {}\r\n\r\n",
                    server_name,
                    dns_query[..query_size].len()
                );
            let data = [http.as_bytes(), &dns_query[..query_size]].concat();
            c.writer().write(&data).unwrap();
            // dbg!("c.writer()");

            // Handle sending request
            loop {
                // dbg!("Handle sending request");
                if c.wants_write() {
                    let written = c.write_tls(&mut tcp).unwrap();
                    if written != 0 {
                        break;
                    }
                }
                sleep(Duration::from_millis(50));
            }
            // Handle Reciving Data
            // dbg!("Handle Reciving Data");
            let mut http_resp = [0u8; 8196];
            let http_resp_size;
            'rt: loop {
                if c.wants_read() {
                    c.read_tls(&mut tcp).unwrap();
                    let stat = c.process_new_packets().unwrap();
                    if stat.peer_has_closed() {
                        break 'main;
                    }

                    let wp = c.reader().read(&mut http_resp);
                    if wp.is_ok() {
                        http_resp_size = wp.unwrap();
                        break 'rt;
                    }
                }
                sleep(Duration::from_millis(50));
            }

            udp.send_to(
                &http_resp[catch_in_buff("\r\n\r\n".as_bytes(), &http_resp).1..http_resp_size],
                addr,
            )
            .unwrap_or(0);
            // dbg!("success");
        }
    }
}
