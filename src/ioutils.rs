#[inline(always)]
pub async fn read_buffered<R: tokio::io::AsyncRead + Unpin>(
    buf: &mut tokio::io::ReadBuf<'_>,
    r: &mut R,
) -> tokio::io::Result<()> {
    let mut pinned = std::pin::Pin::new(r);
    loop {
        tokio::task::yield_now().await;
        if std::future::poll_fn(|cx| match pinned.as_mut().poll_read(cx, buf) {
            std::task::Poll::Pending => {
                if buf.filled().is_empty() {
                    std::task::Poll::Pending
                } else {
                    // nothing to read anymore
                    std::task::Poll::Ready(Ok(true))
                }
            }
            std::task::Poll::Ready(Ok(_)) => {
                if buf.filled().is_empty() {
                    std::task::Poll::Ready(Err(tokio::io::Error::other("EOF")))
                } else if buf.remaining() == 0 {
                    // buf full
                    std::task::Poll::Ready(Ok(true))
                } else {
                    // continue reading
                    std::task::Poll::Ready(Ok(false))
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        })
        .await?
        {
            break;
        }
    }
    Ok(())
}

#[inline(always)]
pub async fn read_buffered_timeout<R: tokio::io::AsyncRead + Unpin>(
    buf: &mut tokio::io::ReadBuf<'_>,
    r: &mut R,
    timeout: std::time::Duration,
) -> tokio::io::Result<()> {
    tokio::time::timeout(timeout, read_buffered(buf, r)).await?
}
