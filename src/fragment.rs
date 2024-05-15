use std::error::Error;
use std::{io::Write, net::TcpStream};

use std::thread::sleep;
use std::time::Duration;
use rustls::ClientConnection;

pub fn fragment_client_hello(c: &mut ClientConnection, tcp: &mut TcpStream)->Result<(),Box<dyn Error>>{
    // Buffer to store TLS Client Hello
    let mut buff = Vec::with_capacity(1024);
    let mut cur = std::io::Cursor::new(&mut buff);
    // Write TLS Client Hello to Buffer
    let l = c.write_tls(&mut cur).unwrap();

    // Split TLS Client Hello into 3 parts
    let packs = (l - 5) / 3;

    // Send TLS Client Hello with 3 steps
    // #1
    let xbuf = [
        &vec![22, 3, 1, 0, buff[5..packs].len() as u8],
        &buff[5..packs],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls)?;
    tcp.flush()?;
    sleep(Duration::from_millis(50));
    // #2
    let xbuf = [
        &vec![22, 3, 1, 0, buff[packs..packs * 2].len() as u8],
        &buff[packs..packs * 2],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls)?;
    tcp.flush()?;
    sleep(Duration::from_millis(50));
    // #3
    let xbuf = [
        &vec![22, 3, 1, 0, buff[packs * 2..].len() as u8],
        &buff[packs * 2..],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls)?;
    tcp.flush()?;

    Ok(())
}