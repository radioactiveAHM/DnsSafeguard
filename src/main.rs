use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::vec;
fn main() {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let rc_config = Arc::new(config);
    let example_com = "cloudflare-dns.com".try_into().unwrap();
    let client = rustls::ClientConnection::new(rc_config, example_com);

    let mut c = client.unwrap();

    let mut tcp = std::net::TcpStream::connect("1.1.1.1:443").unwrap();

    let mut buff = Vec::with_capacity(512);
    let mut cur = std::io::Cursor::new(&mut buff);
    let l = c.write_tls(&mut cur).unwrap();

    let packs = (l - 5) / 3;
    // #1
    let xbuf = [
        &vec![22, 3, 1, 0, buff[5..packs].len() as u8],
        &buff[5..packs],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls).unwrap();
    tcp.flush().unwrap();
    sleep(Duration::from_millis(50));
    // #2
    let xbuf = [
        &vec![22, 3, 1, 0, buff[packs..packs * 2].len() as u8],
        &buff[packs..packs * 2],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls).unwrap();
    tcp.flush().unwrap();
    sleep(Duration::from_millis(50));
    // #3
    let xbuf = [
        &vec![22, 3, 1, 0, buff[packs * 2..].len() as u8],
        &buff[packs * 2..],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls).unwrap();
    tcp.flush().unwrap();

    c.complete_io(&mut tcp).unwrap();

    let udp = UdpSocket::bind("127.0.0.1:53").unwrap();
    loop {
        // dbg!("loop start");
        let mut dns_segment: [u8; 8196] = [0u8; 8196];
        let udp_ok = udp.recv_from(&mut dns_segment);
        if udp_ok.is_err(){
            continue;
        }
        let (segment_size, addr) = udp_ok.unwrap();
        // dbg!("udp.recv_from");
        let http = format!(
            "POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-message\r\nContent-type: application/dns-message\r\nContent-length: {}\r\n\r\n",
            dns_segment[..segment_size].len()
        );
        let data = [http.as_bytes(), &dns_segment[..segment_size]].concat();
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
            sleep(Duration::from_millis(200));
        }
        // Handle Reciving Data
        // dbg!("Handle Reciving Data");
        let mut http_resp = [0u8; 8196];
        let mut http_resp_size = 0;
        loop {
            if c.wants_read() {
                c.read_tls(&mut tcp).unwrap();
                let stat = c.process_new_packets().unwrap();
                if stat.peer_has_closed() {
                    break;
                }

                let wp = c.reader().read(&mut http_resp);
                if wp.is_ok() {
                    http_resp_size = wp.unwrap();
                    break;
                }
            }
            sleep(Duration::from_millis(50));
        }

        udp.send_to(&http_resp[catch_in_buff("\r\n\r\n".as_bytes(), &http_resp).1..http_resp_size], addr)
            .unwrap();
        // dbg!("success");
    }
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
