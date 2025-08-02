pub async fn read_buffered<R: tokio::io::AsyncRead>(
    buf: &mut tokio::io::ReadBuf<'_>,
    pinned: &mut std::pin::Pin<&mut R>,
) -> tokio::io::Result<()> {
    loop {
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
                } else if buf.filled().len() >= buf.capacity() {
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
