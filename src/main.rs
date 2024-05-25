mod config;
mod fragment;
mod tls;

use std::io::{ErrorKind, Read, Write};
use std::net::UdpSocket;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    // Load config
    // If config file does not exist or malformed, panic occurs.
    let conf = config::load_config();

    if conf.ipv6.enable {
        std::thread::spawn(move || {
            dns(
                conf.ipv6.server_name,
                &conf.ipv6.socket_addrs,
                &conf.ipv6.udp_socket_addrs,
                &conf.ipv6.fragmenting,
            )
        });
    }

    dns(
        conf.server_name,
        &conf.socket_addrs,
        &conf.udp_socket_addrs,
        &conf.fragmenting,
    );
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
    (0, 0)
}

fn dns(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
) {
    // Main loop
    let mut tls_handshake_retry = 0u8;
    'main: loop {
        if tls_handshake_retry == 5 {
            println!("Cannot perform TLS handshake");
            panic!();
        }
        println!("New TLS connection");

        // TLS Client
        let mut c = tls::client(server_name.clone()).unwrap();

        // TCP socket for TLS
        let mut tcp = std::net::TcpStream::connect(socket_addrs).unwrap();
        // Set writing timeout to tcp connection
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        // Perform TLS Client Hello fragmenting
        if fragmenting.enable {
            let fraged = match fragmenting.method.as_str() {
                "linear" => fragment::fragment_client_hello(&mut c, &mut tcp),
                "random" => fragment::fragment_client_hello_rand(&mut c, &mut tcp),
                "single" => fragment::fragment_client_hello_pack(&mut c, &mut tcp),
                _ => panic!("Invalid fragment method"),
            };
            if fraged.is_err() {
                tls_handshake_retry = tls_handshake_retry + 1;
                continue 'main;
            }
        }

        // Complete TLS handshake
        match c.complete_io(&mut tcp) {
            Err(e) => {
                // If TLS handshake failed
                println!("{}", e);
                tls_handshake_retry = tls_handshake_retry + 1;
                continue 'main;
            }
            Ok(_) => {
                println!("Connection Established");
            }
        }

        // UDP socket to listen for DNS query
        let udp = UdpSocket::bind(udp_socket_addrs).unwrap();

        let mut dead_conn = false;
        loop {
            if dead_conn {
                println!("connection closed by peer");
                break;
            }
            let mut dns_query: [u8; 8196] = [0u8; 8196];
            let udp_ok = udp.recv_from(&mut dns_query);
            if udp_ok.is_err() {
                continue;
            }
            let (query_size, addr) = udp_ok.unwrap();

            let http_req = [
                b"POST /dns-query HTTP/1.1\r\nHost: ",
                server_name.as_bytes(),
                b"\r\nAccept: application/dns-message\r\nContent-type: application/dns-message\r\nContent-length: ",
                dns_query[..query_size].len().to_string().as_bytes(),
                b"\r\n\r\n",
                &dns_query[..query_size]
            ].concat();

            // Write http request as plaintext to tls container
            c.writer().write(&http_req).unwrap();

            // Handle sending request
            loop {
                if c.wants_write() {
                    match c.write_tls(&mut tcp) {
                        Ok(_) => break,
                        Err(e) => {
                            if e.kind() == ErrorKind::TimedOut
                                || e.kind() == ErrorKind::ConnectionAborted
                                || e.kind() == ErrorKind::ConnectionRefused
                                || e.kind() == ErrorKind::ConnectionReset
                            {
                                // Connection is dead
                                // dbg!("Connection dead while write tls");
                                c.send_close_notify();
                                continue 'main;
                            }
                        }
                    }
                }
                sleep(Duration::from_millis(50));
            }
            // Handle Reciving Data
            let mut http_resp = [0u8; 8196];
            let http_resp_size;
            'rt: loop {
                if c.wants_read() {
                    let rtls_e = c.read_tls(&mut tcp);
                    if rtls_e.is_err() {
                        let e = rtls_e.unwrap_err();
                        if e.kind() == ErrorKind::TimedOut
                            || e.kind() == ErrorKind::ConnectionAborted
                            || e.kind() == ErrorKind::ConnectionRefused
                            || e.kind() == ErrorKind::ConnectionReset
                        {
                            // Connection is dead
                            // dbg!("Connection dead while read_tls");
                            c.send_close_notify();
                            continue 'main;
                        }
                    }
                    let stat = c.process_new_packets();
                    if stat.is_err() {
                        c.send_close_notify();
                        continue 'main;
                    }
                    if stat.unwrap().peer_has_closed() {
                        dead_conn = true;
                    }

                    let wp = c.reader().read(&mut http_resp);
                    if wp.is_ok() {
                        http_resp_size = wp.unwrap();
                        break 'rt;
                    }
                }
                sleep(Duration::from_millis(50));
            }

            let body =
                &http_resp[catch_in_buff("\r\n\r\n".as_bytes(), &http_resp).1..http_resp_size];

            if body.is_empty() {
                continue;
            }
            udp.send_to(body, addr).unwrap_or(0);
        }
    }
}
