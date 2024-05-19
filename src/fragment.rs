use std::error::Error;
use std::{io::Write, net::TcpStream};

use rand::Rng;
use rustls::ClientConnection;
use std::thread::sleep;
use std::time::Duration;

/// 3 TCP segments with TLS client hello pack
#[allow(dead_code)]
pub fn fragment_client_hello(
    c: &mut ClientConnection,
    tcp: &mut TcpStream,
) -> Result<(), Box<dyn Error>> {
    // Buffer to store TLS Client Hello
    let mut buff = Vec::with_capacity(1024 * 4);
    let mut cur = std::io::Cursor::new(&mut buff);
    // Write TLS Client Hello to Buffer
    let l = c.write_tls(&mut cur).unwrap();

    // Split TLS Client Hello into 3 parts
    let packs = (l - 5) / 3;

    // Send TLS Client Hello with 3 steps
    // #1
    let xbuf = [&[22, 3, 1, 0, buff[5..packs].len() as u8], &buff[5..packs]];
    let xtls = xbuf.concat();
    tcp.write(&xtls)?;
    tcp.flush()?;
    sleep(Duration::from_millis(50));
    // #2
    let xbuf = [
        &[22, 3, 1, 0, buff[packs..packs * 2].len() as u8],
        &buff[packs..packs * 2],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls)?;
    tcp.flush()?;
    sleep(Duration::from_millis(50));
    // #3
    let xbuf = [
        &[22, 3, 1, 0, buff[packs * 2..].len() as u8],
        &buff[packs * 2..],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls)?;
    tcp.flush()?;

    Ok(())
}

/// random TCP segments with TLS client hello pack
#[allow(dead_code)]
pub fn fragment_client_hello_rand(
    c: &mut ClientConnection,
    tcp: &mut TcpStream,
) -> Result<(), Box<dyn Error>> {
    // Buffer to store TLS Client Hello
    let mut buff = Vec::with_capacity(1024 * 4);
    let mut cur = std::io::Cursor::new(&mut buff);
    // Write TLS Client Hello to Buffer
    c.write_tls(&mut cur).unwrap();

    // Split TLS Client Hello into chunks
    let mut mr_randy = rand::rngs::OsRng::default();
    let mut written = 5;

    // Send TLS Client Hello with random chunks
    loop {
        let chunck_size = mr_randy.gen_range(10..buff.len());
        if chunck_size + written >= buff.len() {
            let xbuf = [
                &[22, 3, 1, 0, buff[written..].len() as u8],
                &buff[written..],
            ];
            let xtls = xbuf.concat();
            tcp.write(&xtls)?;
            tcp.flush()?;
            break;
        } else {
            let xbuf = [
                &[
                    22,
                    3,
                    1,
                    0,
                    buff[written..(chunck_size + written)].len() as u8,
                ],
                &buff[written..(chunck_size + written)],
            ];
            let xtls = xbuf.concat();
            tcp.write(&xtls)?;
            tcp.flush()?;
            written = written + chunck_size;
            sleep(Duration::from_millis(mr_randy.gen_range(10..21)));
        }
    }

    Ok(())
}

/// 2 packs of TLS client hello in one tcp segment
#[allow(dead_code)]
pub fn fragment_client_hello_pack(
    c: &mut ClientConnection,
    tcp: &mut TcpStream,
) -> Result<(), Box<dyn Error>> {
    // Buffer to store TLS Client Hello
    let mut buff = Vec::with_capacity(1024 * 4);
    let mut cur = std::io::Cursor::new(&mut buff);
    // Write TLS Client Hello to Buffer
    let l = c.write_tls(&mut cur).unwrap();
    let psize = (l - 5) / 2;
    let xtls = [
        [&[22, 3, 1, 0, buff[5..psize].len() as u8], &buff[5..psize]].concat(),
        [&[22, 3, 1, 0, buff[psize..].len() as u8], &buff[psize..]].concat(),
    ]
    .concat();
    tcp.write(&xtls)?;
    tcp.flush()?;

    Ok(())
}
