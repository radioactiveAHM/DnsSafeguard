use tokio::io::AsyncReadExt;

pub async fn read_buffered_timeout<R: tokio::io::AsyncRead + Unpin>(
	buf: &mut tokio::io::ReadBuf<'_>,
	r: &mut R,
	timeout: std::time::Duration,
) -> tokio::io::Result<usize> {
	tokio::time::timeout(timeout, r.read_buf(buf)).await?
}
