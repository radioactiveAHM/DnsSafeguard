struct UdpRecv<'a>(&'a tokio::net::UdpSocket, &'a mut tokio::io::ReadBuf<'a>);

impl<'a> Future for UdpRecv<'a> {
	type Output = tokio::io::Result<(usize, std::net::SocketAddr)>;
	#[inline(always)]
	fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
		let coop = std::task::ready!(tokio::task::coop::poll_proceed(cx));
		let this = &mut *self;
		let polling = this
			.0
			.poll_recv_from(cx, this.1)
			.map_ok(|addr| (this.1.filled().len(), addr));
		if polling.is_ready() {
			coop.made_progress();
		}
		polling
	}
}

#[inline(always)]
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
	let poll_recv = UdpRecv(udp, &mut buf);
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

#[inline(always)]
pub async fn recv_timeout(
	udp: &tokio::net::UdpSocket,
	dur: Option<u64>,
	buf: &mut [u8],
) -> Result<(usize, std::net::SocketAddr), tokio::io::Error> {
	let mut buf = tokio::io::ReadBuf::new(buf);
	let poll_recv = UdpRecv(udp, &mut buf);
	if let Some(dur) = dur {
		tokio::time::timeout(std::time::Duration::from_secs(dur), poll_recv).await?
	} else {
		poll_recv.await
	}
}
