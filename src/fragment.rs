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

async fn segmentation<IO: AsyncWriteExt + std::marker::Unpin>(
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
    fragment: &[u8],
) -> tokio::io::Result<()> {
    let packet = fragment.len() / fragmenting.segments;
    let mut written = 0;

    loop {
        if written + packet >= fragment.len() {
            let _ = tcp.write(&fragment[written..]).await?;
            tcp.flush().await?;
            break;
        }
        let _ = tcp.write(&fragment[written..written + packet]).await?;
        tcp.flush().await?;
        written += packet;

        sleep(Duration::from_millis(rand::random_range(
            fragmenting.sleep_interval_min..fragmenting.sleep_interval_max,
        )))
        .await;
    }
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
    let mut written = 5;

    let mut fragmented_tls_hello_buf = [0; 512];
    let mut fragmented_tls_hello = Buffering(&mut fragmented_tls_hello_buf, 0);
    // Send TLS Client Hello with random chunks
    loop {
        let chunck_size =
            rand::random_range(fragmenting.fragment_size_min..fragmenting.fragment_size_max);
        if chunck_size + written >= l {
            let fragment = fragmented_tls_hello
                .reset()
                .write(&[22, 3, 1, 0, buff.buff[written..l].len() as u8])
                .write(&buff.buff[written..l])
                .get();
            segmentation(tcp, fragmenting, fragment).await?;
            break;
        } else {
            let fragment = fragmented_tls_hello
                .reset()
                .write(&[
                    22,
                    3,
                    1,
                    0,
                    buff.buff[written..(chunck_size + written)].len() as u8,
                ])
                .write(&buff.buff[written..(chunck_size + written)])
                .get();
            segmentation(tcp, fragmenting, fragment).await?;
            written += chunck_size;
        }
    }

    Ok(())
}

/// 2 packs of TLS client hello in one tcp segment
pub async fn fragment_client_hello_pack<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
) -> tokio::io::Result<()> {
    // Buffer to store TLS Client Hello
    let mut b = TlsHello {
        buff: [0; 1024 * 4],
    };
    // Write TLS Client Hello to Buffer
    let l = c.write_tls(&mut b)?;

    let mut written = 5;
    let mut fragmented_tls_hello_buf = [0; 512];
    let mut fragmented_tls_hello = Buffering(&mut fragmented_tls_hello_buf, 0);
    loop {
        let size = rand::random_range(fragmenting.fragment_size_min..fragmenting.fragment_size_max);
        if written + size >= l {
            let size = b.buff[written..l].len();
            fragmented_tls_hello
                .write(&[22, 3, 1, 0, size as u8])
                .write(&b.buff[written..l]);
            break;
        }
        fragmented_tls_hello
            .write(&[22, 3, 1, 0, size as u8])
            .write(&b.buff[written..written + size]);
        written += size;
    }

    let _ = tcp.write(fragmented_tls_hello.get()).await?;
    tcp.flush().await?;

    Ok(())
}
