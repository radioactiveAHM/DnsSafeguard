use std::{net::SocketAddr, sync::Arc};

use quinn::{RecvStream, SendStream};
use tokio::{
	sync::Mutex,
	time::{sleep, timeout},
};

use crate::{
	CONFIG,
	doh3::quic_setup,
	rule::rulecheck,
	utils::{convert_two_u8s_to_u16_be, convert_u16_to_two_u8s_be},
};

pub async fn doq() {
	let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());

	let mut endpoint = quic_setup(
		CONFIG.remote_addrs,
		&CONFIG.noise,
		&CONFIG.quic,
		"doq",
		&CONFIG.interface,
	)
	.await;

	let mut tank: Option<(Box<[u8; 514]>, usize, SocketAddr)> = None;

	let mut connecting_retry = 0u8;
	loop {
		if connecting_retry == 3 {
			connecting_retry = 0;
			endpoint = quic_setup(
				CONFIG.remote_addrs,
				&CONFIG.noise,
				&CONFIG.quic,
				"doq",
				&CONFIG.interface,
			)
			.await;
		}
		log::info!("QUIC connecting");
		// Connect to dns server
		let connecting = endpoint.connect(CONFIG.remote_addrs, &CONFIG.server_name).unwrap();

		let conn = {
			let timing = timeout(std::time::Duration::from_secs(CONFIG.quic.connecting_timeout), async {
				let connecting = connecting.into_0rtt();
				if let Ok((conn, rtt)) = connecting {
					rtt.await;
					log::info!("QUIC 0RTT connection established");
					Ok(conn)
				} else {
					let conn = endpoint
						.connect(CONFIG.remote_addrs, &CONFIG.server_name)
						.unwrap()
						.await;
					if conn.is_ok() {
						log::info!("QUIC connection established");
					}
					conn
				}
			})
			.await;

			if let Ok(pending) = timing {
				pending
			} else {
				connecting_retry += 1;
				log::warn!("connecting timeout");
				sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
				continue;
			}
		};

		if conn.is_err() {
			connecting_retry += 1;
			log::warn!("{}", conn.unwrap_err());
			sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
			continue;
		}
		connecting_retry = 0;

		let quic = conn.unwrap();
		let dead_conn = Arc::new(Mutex::new(false));

		let q2 = quic.clone();
		let dead_conn2 = dead_conn.clone();
		let watcher = tokio::spawn(async move {
			log::warn!("watcher: {}", q2.closed().await);
			*dead_conn2.lock().await = true;
		});

		if tank.is_some() {
			let dead = dead_conn.clone();
			let udp = udp.clone();
			match quic.open_bi().await {
				Ok(bistream) => {
					let stream_id = bistream.0.id();
					let (dns_query, query_size, addr) = tank.unwrap();
					tokio::spawn(async move {
						if let Err(e) = send_dq(bistream, (*dns_query, query_size), addr, udp).await {
							log::warn!("{stream_id}: {e}");
							if e.kind() == std::io::ErrorKind::TimedOut {
								*dead.lock().await = true;
							}
						}
					});
				}
				Err(e) => {
					log::warn!("{e}");
					continue;
				}
			}
			tank = None;
		}

		let mut dns_query = [0u8; 514];
		loop {
			let dead = dead_conn.clone();
			let udp = udp.clone();
			if *dead.lock().await {
				watcher.abort();
				break;
			}

			let message =
				crate::keepalive::recv_timeout_with(&udp, CONFIG.connection_keep_alive, &mut dns_query[2..], async {
					match quic.open_bi().await {
						Ok((mut send, mut recv)) => {
							let _ = send.write(&[]).await;
							let _ = send.finish();
							let _ = recv.read_chunk(1024 * 4, false).await;
						}
						Err(e) => {
							log::warn!("{e}");
							*dead.lock().await = true;
						}
					};
				})
				.await;

			// Recive dns query
			if let Some(Ok((query_size, addr))) = message {
				// rule check
				if (CONFIG.rules.is_some()
					&& rulecheck(&CONFIG.rules, &mut dns_query[2..query_size + 2], addr, udp.clone()).await)
					|| query_size < 12
				{
					continue;
				}

				if *dead.lock().await {
					tank = Some((Box::new(dns_query), query_size, addr));
					watcher.abort();
					break;
				}

				match quic.open_bi().await {
					Ok(bistream) => {
						let stream_id = bistream.0.id();
						tokio::spawn(async move {
							if let Err(e) = send_dq(bistream, (dns_query, query_size), addr, udp).await {
								log::warn!("{stream_id}: {e}");
								if e.kind() == std::io::ErrorKind::TimedOut {
									*dead.lock().await = true;
								}
							}
						});
					}
					Err(e) => {
						log::warn!("{e}");
						tank = Some((Box::new(dns_query), query_size, addr));
						watcher.abort();
						break;
					}
				}
			}
		}
	}
}

#[inline(always)]
async fn send_dq(
	(mut send, mut recv): (SendStream, RecvStream),
	mut dns_query: ([u8; 514], usize),
	addr: SocketAddr,
	udp: Arc<tokio::net::UdpSocket>,
) -> tokio::io::Result<()> {
	[dns_query.0[0], dns_query.0[1]] = convert_u16_to_two_u8s_be(dns_query.1 as u16);
	send.write_all(&dns_query.0[..dns_query.1 + 2]).await?;
	send.finish()?;

	let mut buf = [0u8; 1024 * 8];
	let mut buf_rb = tokio::io::ReadBuf::new(&mut buf);
	recv_timeout(
		&mut recv,
		&mut buf_rb,
		std::time::Duration::from_secs(CONFIG.response_timeout),
	)
	.await?;

	if buf_rb.filled().is_empty() {
		log::warn!("{} closed", send.id());
		return Ok(());
	}

	let message_size = convert_two_u8s_to_u16_be([buf_rb.filled()[0], buf_rb.filled()[1]]) as usize;
	if message_size == 0 {
		return Err(tokio::io::Error::other("malformed dns query response"));
	}

	let mut size = buf_rb.filled().len();
	loop {
		if size - 2 >= message_size {
			break;
		}
		recv_timeout(
			&mut recv,
			&mut buf_rb,
			std::time::Duration::from_secs(CONFIG.response_timeout),
		)
		.await?;
		if size == buf_rb.filled().len() {
			log::warn!(
				"{} closed: target bytes {} recved bytes {}",
				send.id(),
				message_size,
				size
			);
			return Ok(());
		}
		size = buf_rb.filled().len();
	}

	if CONFIG.overwrite.is_some() {
		crate::ipoverwrite::overwrite_ip(buf_rb.filled_mut(), &CONFIG.overwrite);
	}
	let _ = udp.send_to(&buf_rb.filled()[2..], addr).await;
	Ok(())
}

struct Recv<'a, 'b>(&'a mut RecvStream, &'a mut tokio::io::ReadBuf<'b>);
impl<'a, 'b> Future for Recv<'a, 'b> {
	type Output = tokio::io::Result<()>;
	#[inline(always)]
	fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
		let coop = std::task::ready!(tokio::task::coop::poll_proceed(cx));
		let this = &mut *self;
		let poll = std::task::ready!(this.0.poll_read_buf(cx, this.1));
		coop.made_progress();
		std::task::Poll::Ready(poll.map_err(tokio::io::Error::other))
	}
}

#[inline(always)]
async fn recv_timeout(
	recv: &mut RecvStream,
	buf: &mut tokio::io::ReadBuf<'_>,
	dur: std::time::Duration,
) -> tokio::io::Result<()> {
	tokio::time::timeout(dur, Recv(recv, buf)).await?
}
