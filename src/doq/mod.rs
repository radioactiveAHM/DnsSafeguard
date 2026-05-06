use bytes::BufMut;
use quinn::{RecvStream, SendStream};
use tokio::time::{sleep, timeout};

use crate::{
	CONFIG,
	doh3::quic_setup,
	rule::rulecheck,
	utils::{convert_two_u8s_to_u16_be, convert_u16_to_two_u8s_be},
};

pub async fn doq(server: &'static crate::config::Server, rpipe: crate::pipe::ReceiverPipe) {
	let mut endpoint = quic_setup(
		server.remote_addrs,
		&CONFIG.noiser,
		&CONFIG.quic,
		"doq",
		&CONFIG.interface,
	)
	.await;

	let mut tank: Option<crate::pipe::Message> = None;
	let disconnected = crate::disconnected::Disconnected::new();

	let mut connecting_retry = 0u8;
	loop {
		if connecting_retry == 3 {
			connecting_retry = 0;
			endpoint = quic_setup(
				server.remote_addrs,
				&CONFIG.noiser,
				&CONFIG.quic,
				"doq",
				&CONFIG.interface,
			)
			.await;
		}
		log::info!("{}: QUIC connecting", server.id);
		// Connect to dns server
		let connecting = endpoint.connect(server.remote_addrs, &server.sni).unwrap();

		let conn = {
			let timing = timeout(std::time::Duration::from_secs(CONFIG.quic.connecting_timeout), async {
				let connecting = connecting.into_0rtt();
				if let Ok((conn, rtt)) = connecting {
					rtt.await;
					log::info!("{}: QUIC 0RTT connection established", server.id);
					Ok(conn)
				} else {
					let conn = endpoint.connect(server.remote_addrs, &server.sni).unwrap().await;
					if conn.is_ok() {
						log::info!("{}: QUIC connection established", server.id);
					}
					conn
				}
			})
			.await;

			if let Ok(pending) = timing {
				pending
			} else {
				connecting_retry += 1;
				log::warn!("{}: connecting timeout", server.id);
				sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
				continue;
			}
		};

		if let Err(e) = conn {
			log::warn!("{}: {e}", server.id);
			connecting_retry += 1;
			sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
			continue;
		}
		connecting_retry = 0;

		let quic = conn.unwrap();
		disconnected.connect();

		let q2 = quic.clone();
		let _disconnected = disconnected.clone();
		let watcher = tokio::spawn(async move {
			log::warn!("{}: watcher: {}", server.id, q2.closed().await);
			_disconnected.disconnect();
		});

		if tank.is_some() {
			match quic.open_bi().await {
				Ok(bistream) => {
					let stream_id = bistream.0.id();
					let message = tank.unwrap();
					tokio::spawn(async move {
						if let Err(e) = send_dq(message, bistream).await {
							log::warn!("{}: {stream_id}: {e}", server.id);
						}
					});
				}
				Err(e) => {
					log::warn!("{}: {e}", server.id);
					continue;
				}
			}
			tank = None;
		}

		loop {
			let disconnected = disconnected.clone();
			if disconnected.get() {
				watcher.abort();
				break;
			}

			let message = crate::keepalive::pipe_recv_timeout_with(&rpipe, CONFIG.connection_keep_alive, async {
				match quic.open_bi().await {
					Ok((mut send, _)) => {
						if send.write(&[]).await.is_ok() {
							let _ = send.finish();
						}
					}
					Err(e) => {
						log::warn!("{}: {e}", server.id);
						disconnected.disconnect();
					}
				};
			})
			.await;

			// Recive dns query
			if let Some(message) = message
				&& let Some(message) = rulecheck(CONFIG.rules.is_some(), &CONFIG.rules, message).await
			{
				if disconnected.get() {
					tank = Some(message);
					watcher.abort();
					break;
				}

				match quic.open_bi().await {
					Ok(bistream) => {
						let stream_id = bistream.0.id();
						tokio::spawn(async move {
							if let Err(e) = send_dq(message, bistream).await {
								log::warn!("{}: {stream_id}: {e}", server.id);
								if e.kind() == std::io::ErrorKind::TimedOut {
									disconnected.disconnect();
								}
							}
						});
					}
					Err(e) => {
						log::warn!("{}: {e}", server.id);
						tank = Some(message);
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
	message: crate::pipe::Message,
	(mut send, mut recv): (SendStream, RecvStream),
) -> tokio::io::Result<()> {
	let mut dq = Vec::with_capacity(message.message_slice().len() + 2);
	dq.extend_from_slice(&convert_u16_to_two_u8s_be(message.message_slice().len() as u16));
	dq.extend_from_slice(message.message_slice());
	send.write_all(&dq).await?;
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
	message.send_response_slice(&data[2..]).await;
	Ok(())
}

#[inline(always)]
async fn recv_timeout(recv: &mut RecvStream, dur: std::time::Duration) -> tokio::io::Result<Option<quinn::Chunk>> {
	Ok(tokio::time::timeout(dur, recv.read_chunk(1024 * 64, true)).await??)
}
