use std::{net::SocketAddr, sync::Arc};

use bytes::BufMut;
use quinn::{RecvStream, SendStream};
use tokio::time::{sleep, timeout};

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
	let disconnected = crate::disconnected::Disconnected::new();

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
		disconnected.connect();

		let q2 = quic.clone();
		let _disconnected = disconnected.clone();
		let watcher = tokio::spawn(async move {
			log::warn!("watcher: {}", q2.closed().await);
			_disconnected.disconnect();
		});

		if tank.is_some() {
			let udp = udp.clone();
			match quic.open_bi().await {
				Ok(bistream) => {
					let stream_id = bistream.0.id();
					let (dns_query, query_size, addr) = tank.unwrap();
					tokio::spawn(async move {
						if let Err(e) = send_dq(bistream, (*dns_query, query_size), addr, udp).await {
							log::warn!("{stream_id}: {e}");
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
			let disconnected = disconnected.clone();
			let udp = udp.clone();
			if disconnected.get() {
				watcher.abort();
				break;
			}

			let message =
				crate::keepalive::recv_timeout_with(&udp, CONFIG.connection_keep_alive, &mut dns_query[2..], async {
					match quic.open_bi().await {
						Ok((mut send, _)) => {
							if send.write(&[]).await.is_ok() {
								let _ = send.finish();
							}
						}
						Err(e) => {
							log::warn!("{e}");
							disconnected.disconnect();
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

				if disconnected.get() {
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
									disconnected.disconnect();
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

	let timeout_dur = std::time::Duration::from_secs(CONFIG.response_timeout);
	let mut data = bytes::BytesMut::from(
		recv_timeout(&mut recv, timeout_dur)
			.await?
			.ok_or(tokio::io::Error::other("stream closed without data"))?
			.bytes,
	);
	if data.is_empty() {
		log::warn!("{} closed", send.id());
		return Ok(());
	}

	let message_size = convert_two_u8s_to_u16_be([data[0], data[1]]) as usize;
	if message_size == 0 {
		return Err(tokio::io::Error::other("malformed dns query response"));
	}

	loop {
		if data.len() - 2 >= message_size {
			break;
		}
		data.put(
			recv_timeout(&mut recv, timeout_dur)
				.await?
				.ok_or(tokio::io::Error::other("stream closed with incomplete data"))?
				.bytes,
		);
	}

	if CONFIG.overwrite.is_some() {
		crate::ipoverwrite::overwrite_ip(&mut data, &CONFIG.overwrite);
	}
	let _ = udp.send_to(&data[2..], addr).await;
	Ok(())
}

#[inline(always)]
async fn recv_timeout(recv: &mut RecvStream, dur: std::time::Duration) -> tokio::io::Result<Option<quinn::Chunk>> {
	Ok(tokio::time::timeout(dur, recv.read_chunk(1024 * 64, true)).await??)
}
