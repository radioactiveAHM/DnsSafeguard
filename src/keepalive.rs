pub async fn recv_timeout_with<Fu>(
    udp: &tokio::net::UdpSocket,
    dur: Option<u64>,
    buf: &mut [u8],
    f: Fu,
) -> Option<Result<(usize, std::net::SocketAddr), tokio::io::Error>>
where
    Fu: Future<Output = ()>,
{
    let mut buf = tokio::io::ReadBuf::new(buf);
    let poll_recv = std::future::poll_fn(|cx| match udp.poll_recv_from(cx, &mut buf) {
        std::task::Poll::Pending => std::task::Poll::Pending,
        std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        std::task::Poll::Ready(Ok(addr)) => std::task::Poll::Ready(Ok((buf.filled().len(), addr))),
    });
    tokio::task::yield_now().await;
    if let Some(dur) = dur {
        match tokio::time::timeout(std::time::Duration::from_secs(dur), poll_recv).await {
            Ok(message) => Some(message),
            Err(_) => {
                f.await;
                None
            }
        }
    } else {
        Some(poll_recv.await)
    }
}

pub async fn recv_timeout(
    udp: &tokio::net::UdpSocket,
    dur: Option<u64>,
    buf: &mut [u8],
) -> Result<(usize, std::net::SocketAddr), tokio::io::Error> {
    let mut buf = tokio::io::ReadBuf::new(buf);
    let poll_recv = std::future::poll_fn(|cx| match udp.poll_recv_from(cx, &mut buf) {
        std::task::Poll::Pending => std::task::Poll::Pending,
        std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        std::task::Poll::Ready(Ok(addr)) => std::task::Poll::Ready(Ok((buf.filled().len(), addr))),
    });
    tokio::task::yield_now().await;
    if let Some(dur) = dur {
        tokio::time::timeout(std::time::Duration::from_secs(dur), poll_recv).await?
    } else {
        poll_recv.await
    }
}
