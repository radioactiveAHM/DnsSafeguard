use rand::Rng;
use std::time::Duration;
use tokio::{io::AsyncWriteExt, time::sleep};
use tokio_rustls::rustls::ClientConnection;

/// 3 TCP segments with TLS client hello pack
pub async fn fragment_client_hello<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
) {
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
    tcp.write(&xtls).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
    sleep(Duration::from_millis(50)).await;
    // #2
    let xbuf = [
        &[22, 3, 1, 0, buff[packs..packs * 2].len() as u8],
        &buff[packs..packs * 2],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
    sleep(Duration::from_millis(50)).await;
    // #3
    let xbuf = [
        &[22, 3, 1, 0, buff[packs * 2..].len() as u8],
        &buff[packs * 2..],
    ];
    let xtls = xbuf.concat();
    tcp.write(&xtls).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
}

/// random TCP segments with TLS client hello pack
pub async fn fragment_client_hello_rand<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
) {
    // Buffer to store TLS Client Hello
    let mut buff = Vec::with_capacity(1024 * 4);
    let mut cur = std::io::Cursor::new(&mut buff);
    // Write TLS Client Hello to Buffer
    c.write_tls(&mut cur).unwrap();

    // Split TLS Client Hello into chunks
    let mut mr_randy = rand::rngs::OsRng;
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
            tcp.write(&xtls).await.unwrap_or_default();
            tcp.flush().await.unwrap_or_default();
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
            tcp.write(&xtls).await.unwrap_or_default();
            tcp.flush().await.unwrap_or_default();
            written += chunck_size;
            sleep(Duration::from_millis(mr_randy.gen_range(10..21))).await;
        }
    }
}

/// 2 packs of TLS client hello in one tcp segment
pub async fn fragment_client_hello_pack<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
) {
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
    tcp.write(&xtls).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
}

pub async fn fragment_client_hello_jump<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
) {
    let mut mr_randy = rand::rngs::OsRng;
    // Buffer to store TLS Client Hello
    let mut tlshello = Vec::with_capacity(1024 * 4);
    let mut cur = std::io::Cursor::new(&mut tlshello);
    let l = c.write_tls(&mut cur).unwrap();

    let psize = (l - 5) / 2;
    let p1 = [&[22, 3, 1, 0, tlshello[5..psize].len() as u8], &tlshello[5..(psize/2)]].concat();
    tcp.write(&p1).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
    sleep(Duration::from_millis(mr_randy.gen_range(30..60))).await;

    let p2 = &tlshello[(psize/2)..psize];
    tcp.write(&p2).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
    sleep(Duration::from_millis(mr_randy.gen_range(30..60))).await;

    let p3 = [&[22, 3, 1, 0, tlshello[psize..].len() as u8], &tlshello[psize..(psize+(psize/2))]].concat();
    tcp.write(&p3).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
    sleep(Duration::from_millis(mr_randy.gen_range(30..60))).await;

    let p4 = &tlshello[(psize+(psize/2))..];
    tcp.write(&p4).await.unwrap_or_default();
    tcp.flush().await.unwrap_or_default();
    sleep(Duration::from_millis(mr_randy.gen_range(30..60))).await;
}
