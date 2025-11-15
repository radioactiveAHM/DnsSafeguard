use tokio::{io::AsyncWriteExt, time::sleep};
use tokio_rustls::rustls::ClientConnection;

async fn segmentation<IO: AsyncWriteExt + std::marker::Unpin>(
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
    fragment: &[u8],
) -> tokio::io::Result<()> {
    let sleep_interval = crate::utils::parse_range(&fragmenting.sleep_interval)
        .expect("failed to parse fragmenting sleep_interval range");
    for segment in
        fragment.chunks((fragment.len() as f32 / fragmenting.segments as f32).ceil() as usize)
    {
        tcp.write_all(segment).await?;
        tcp.flush().await?;

        sleep(std::time::Duration::from_millis(rand::random_range(
            sleep_interval.clone(),
        )))
        .await;
    }
    Ok(())
}

pub async fn fragment_client_hello_rand<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
) -> tokio::io::Result<()> {
    let fragment_size = crate::utils::parse_range(&fragmenting.fragment_size)
        .expect("failed to parse fragmenting fragment_size range");
    if fragment_size.start == 0 {
        panic!("minimum fragment size can not be 0");
    } else if fragment_size.end > 255 {
        panic!("maximum fragment size can not be bigger than 255");
    }

    let mut tls_hello = Vec::with_capacity(1024 * 8);
    let l = c.write_tls(&mut tls_hello)?;

    let mut written = 5;
    let mut fragmented_tls_hello = Vec::with_capacity(256);

    loop {
        let chunck_size: usize = rand::random_range(fragment_size.clone());
        if chunck_size + written >= l {
            fragmented_tls_hello.clear();
            fragmented_tls_hello.extend_from_slice(&[
                22,
                3,
                1,
                0,
                tls_hello[written..l].len() as u8,
            ]);
            fragmented_tls_hello.extend_from_slice(&tls_hello[written..l]);
            segmentation(tcp, fragmenting, &fragmented_tls_hello).await?;
            break;
        } else {
            fragmented_tls_hello.clear();
            fragmented_tls_hello.extend_from_slice(&[
                22,
                3,
                1,
                0,
                tls_hello[written..(chunck_size + written)].len() as u8,
            ]);
            fragmented_tls_hello.extend_from_slice(&tls_hello[written..(chunck_size + written)]);
            segmentation(tcp, fragmenting, &fragmented_tls_hello).await?;
            written += chunck_size;
        }
    }
    Ok(())
}

pub async fn fragment_client_hello_pack<IO: AsyncWriteExt + std::marker::Unpin>(
    c: &mut ClientConnection,
    tcp: &mut IO,
    fragmenting: &crate::config::Fragmenting,
) -> tokio::io::Result<()> {
    let fragment_size = crate::utils::parse_range(&fragmenting.fragment_size)
        .expect("failed to parse fragmenting fragment_size range");
    if fragment_size.start == 0 {
        panic!("minimum fragment size can not be 0");
    } else if fragment_size.end > 255 {
        panic!("maximum fragment size can not be bigger than 255");
    }

    let mut tls_hello = Vec::with_capacity(512);
    let l = c.write_tls(&mut tls_hello)?;

    let mut written = 5;
    let mut fragmented_tls_hello = Vec::with_capacity(1024 * 8);
    loop {
        let size: usize = rand::random_range(fragment_size.clone());
        if written + size >= l {
            let size = tls_hello[written..l].len();
            fragmented_tls_hello.extend_from_slice(&[22, 3, 1, 0, size as u8]);
            fragmented_tls_hello.extend_from_slice(&tls_hello[written..l]);
            break;
        }
        fragmented_tls_hello.extend_from_slice(&[22, 3, 1, 0, size as u8]);
        fragmented_tls_hello.extend_from_slice(&tls_hello[written..written + size]);
        written += size;
    }

    segmentation(tcp, fragmenting, &fragmented_tls_hello).await?;

    Ok(())
}
