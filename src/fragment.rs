use rand::Rng;
use std::time::Duration;
use tokio::{io::AsyncWriteExt, time::sleep};
use tokio_rustls::rustls::ClientConnection;

use crate::utils::Buffering;

struct TlsHello {
    buff: [u8; 1024 * 4],
}
impl std::io::Write for TlsHello {
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.buff.len() {
            Err(tokio::io::Error::from(tokio::io::ErrorKind::StorageFull))
        } else {
            self.buff[..buf.len()].copy_from_slice(buf);
            Ok(buf.len())
        }
    }
    fn flush(&mut self) -> tokio::io::Result<()> {
        Ok(())
    }
}

/// 3 TCP segments with TLS client hello pack
pub async fn fragment_client_hello<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
) -> tokio::io::Result<()> {
    let mut mr_randy = rand::rngs::OsRng;
    // Buffer to store TLS Client Hello
    let mut buff = TlsHello {
        buff: [0; 1024 * 4],
    };
    let l = c.write_tls(&mut buff)?;

    // Split TLS Client Hello into 3 parts
    let packs = (l - 5) / 3;

    let mut fragmented_tls_hello_buf = [0; 512];
    let mut fragmented_tls_hello = Buffering(&mut fragmented_tls_hello_buf, 0);
    // Send TLS Client Hello with 3 steps
    // #1
    let _ = tcp
        .write(
            fragmented_tls_hello
                .write(&[22, 3, 1, 0, buff.buff[5..packs].len() as u8])
                .write(&buff.buff[5..packs])
                .get(),
        )
        .await?;
    tcp.flush().await?;
    sleep(Duration::from_millis(mr_randy.gen_range(
        fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
    )))
    .await;
    // #2
    let _ = tcp
        .write(
            fragmented_tls_hello
                .reset()
                .write(&[22, 3, 1, 0, buff.buff[packs..packs * 2].len() as u8])
                .write(&buff.buff[packs..packs * 2])
                .get(),
        )
        .await?;
    tcp.flush().await?;
    sleep(Duration::from_millis(mr_randy.gen_range(
        fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
    )))
    .await;
    // #3
    let _ = tcp
        .write(
            fragmented_tls_hello
                .reset()
                .write(&[22, 3, 1, 0, buff.buff[packs * 2..l].len() as u8])
                .write(&buff.buff[packs * 2..l])
                .get(),
        )
        .await?;
    tcp.flush().await?;

    Ok(())
}

/// random TCP segments with TLS client hello pack
pub async fn fragment_client_hello_rand<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
) -> tokio::io::Result<()> {
    // Buffer to store TLS Client Hello
    let mut buff = TlsHello {
        buff: [0; 1024 * 4],
    };
    // Write TLS Client Hello to Buffer
    let l = c.write_tls(&mut buff)?;

    // Split TLS Client Hello into chunks
    let mut mr_randy = rand::rngs::OsRng;
    let mut written = 5;

    let mut fragmented_tls_hello_buf = [0; 512];
    let mut fragmented_tls_hello = Buffering(&mut fragmented_tls_hello_buf, 0);
    // Send TLS Client Hello with random chunks
    loop {
        let chunck_size = mr_randy.gen_range(10..l);
        if chunck_size + written >= l {
            let _ = tcp
                .write(
                    fragmented_tls_hello
                        .reset()
                        .write(&[22, 3, 1, 0, buff.buff[written..l].len() as u8])
                        .write(&buff.buff[written..l])
                        .get(),
                )
                .await?;
            tcp.flush().await?;
            break;
        } else {
            let _ = tcp
                .write(
                    fragmented_tls_hello
                        .reset()
                        .write(&[
                            22,
                            3,
                            1,
                            0,
                            buff.buff[written..(chunck_size + written)].len() as u8,
                        ])
                        .write(&buff.buff[written..(chunck_size + written)])
                        .get(),
                )
                .await?;
            tcp.flush().await?;
            written += chunck_size;
            sleep(Duration::from_millis(mr_randy.gen_range(
                fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
            )))
            .await;
        }
    }

    Ok(())
}

/// 2 packs of TLS client hello in one tcp segment
pub async fn fragment_client_hello_pack<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
) -> tokio::io::Result<()> {
    // Buffer to store TLS Client Hello
    let mut b = TlsHello {
        buff: [0; 1024 * 4],
    };
    // Write TLS Client Hello to Buffer
    let l = c.write_tls(&mut b)?;
    let psize = (l - 5) / 2;
    let mut fragmented_tls_hello_buf = [0; 512];
    let mut fragmented_tls_hello = Buffering(&mut fragmented_tls_hello_buf, 0);
    fragmented_tls_hello
        .write(&[22, 3, 1, 0, b.buff[5..psize].len() as u8])
        .write(&b.buff[5..psize])
        .write(&[22, 3, 1, 0, b.buff[psize..l].len() as u8])
        .write(&b.buff[psize..l]);
    let _ = tcp.write(fragmented_tls_hello.get()).await?;
    tcp.flush().await?;

    Ok(())
}

pub async fn fragment_client_hello_jump<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
) -> tokio::io::Result<()> {
    let mut mr_randy = rand::rngs::OsRng;
    // Buffer to store TLS Client Hello
    let mut tlshello = TlsHello {
        buff: [0; 1024 * 4],
    };
    let l = c.write_tls(&mut tlshello)?;

    let mut fragmented_tls_hello_buf = [0; 512];
    let mut fragmented_tls_hello = Buffering(&mut fragmented_tls_hello_buf, 0);
    let psize = (l - 5) / 2;
    let _ = tcp
        .write(
            fragmented_tls_hello
                .write(&[22, 3, 1, 0, tlshello.buff[5..psize].len() as u8])
                .write(&tlshello.buff[5..(psize / 2)])
                .get(),
        )
        .await?;
    tcp.flush().await?;
    sleep(Duration::from_millis(mr_randy.gen_range(
        fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
    )))
    .await;

    let _ = tcp.write(&tlshello.buff[(psize / 2)..psize]).await?;
    tcp.flush().await?;
    sleep(Duration::from_millis(mr_randy.gen_range(
        fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
    )))
    .await;

    let _ = tcp
        .write(
            fragmented_tls_hello
                .reset()
                .write(&[22, 3, 1, 0, tlshello.buff[psize..l].len() as u8])
                .write(&tlshello.buff[psize..(psize + (psize / 2))])
                .get(),
        )
        .await?;
    tcp.flush().await?;
    sleep(Duration::from_millis(mr_randy.gen_range(
        fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
    )))
    .await;

    let _ = tcp.write(&tlshello.buff[(psize + (psize / 2))..l]).await?;
    tcp.flush().await?;

    Ok(())
}
