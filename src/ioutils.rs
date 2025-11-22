pub struct Fill<'a, 'b, 'c, R>(pub std::pin::Pin<&'b mut R>, pub &'a mut tokio::io::ReadBuf<'c>);
impl<'a, 'b, 'c, R> Future for Fill<'a, 'b, 'c, R>
where
	R: tokio::io::AsyncRead + Unpin,
{
	type Output = tokio::io::Result<()>;
	#[inline(always)]
	fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
		let coop = std::task::ready!(tokio::task::coop::poll_proceed(cx));
		let this = &mut *self;
		let mut filled = 0;
		loop {
			match this.0.as_mut().poll_read(cx, this.1) {
				std::task::Poll::Pending => {
					if filled == 0 {
						return std::task::Poll::Pending;
					} else {
						coop.made_progress();
						return std::task::Poll::Ready(Ok(()));
					}
				}
				std::task::Poll::Ready(Ok(_)) => {
					coop.made_progress();
					let fill = this.1.filled().len();
					if fill == 0 || filled == fill {
						return std::task::Poll::Ready(Err(tokio::io::Error::other("pipe read EOF")));
					} else if this.1.remaining() == 0 {
						return std::task::Poll::Ready(Ok(()));
					}
					filled = fill;
				}
				std::task::Poll::Ready(Err(e)) => {
					coop.made_progress();
					return std::task::Poll::Ready(Err(e));
				}
			};
		}
	}
}

#[inline(always)]
pub async fn read_buffered_timeout<R: tokio::io::AsyncRead + Unpin>(
	buf: &mut tokio::io::ReadBuf<'_>,
	r: &mut R,
	timeout: std::time::Duration,
) -> tokio::io::Result<()> {
	tokio::time::timeout(timeout, Fill(std::pin::Pin::new(r), buf)).await?
}
