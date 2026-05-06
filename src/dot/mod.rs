use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::{
	CONFIG,
	rule::rulecheck,
	tls,
	utils::{convert_two_u8s_to_u16_be, convert_u16_to_two_u8s_be},
};

enum IdType {
	ZeroID(crate::pipe::Message),
	WithID(crate::pipe::Message),
}

pub async fn dot(server: &'static crate::config::Server, rpipe: crate::pipe::ReceiverPipe) {
	let ctls = tls::tlsconf(vec![b"dot".to_vec()], server.disable_certificate_validation);
	loop {
		log::info!("{}: TLS connecting", server.id);
		let tls = crate::tls::dynamic_tls_conn_gen(server, &["dot"], ctls.clone()).await;
		if let Err(e) = tls {
			log::warn!("{}: {e}", server.id);
			tokio::time::sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
			continue;
		}
		log::info!("{}: TLS connection established", server.id);

		let (r, w) = tokio::io::split(tls.unwrap());

		// Hold dns message ID with it's dns resolver Addr to match
		let waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>> =
			Arc::new(Mutex::new(std::collections::HashMap::new()));

		let waiters2 = waiters.clone();
		let rpipe = rpipe.clone();
		tokio::select! {
			recver = tokio::spawn(recv_query(r, waiters2)) => {
				if let Err(e) = recver {
					log::warn!("{}: {e}", server.id);
				}
			}
			sender = send_query(rpipe, w, waiters) => {
				if let Err(e) = sender {
					log::warn!("{}: {e}", server.id);
				}
			}
		}
	}
}

#[inline(always)]
async fn recv_query<R: tokio::io::AsyncRead + Unpin>(
	mut r: R,
	waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>>,
) -> tokio::io::Result<()> {
	let mut buffer = crate::utils::DeqBuffer::new(1024 * 8);
	let mut reading_buf = [0u8; 1024 * 8];
	let mut reading_buf_rb = tokio::io::ReadBuf::new(&mut reading_buf);
	loop {
		reading_buf_rb.clear();
		crate::ioutils::Fill(std::pin::Pin::new(&mut r), &mut reading_buf_rb).await?;
		buffer.write(reading_buf_rb.filled());
		loop {
			let buffer_slice = buffer.slice();
			let size = buffer_slice.len();
			if size < 12 {
				break;
			}

			let message_size = convert_two_u8s_to_u16_be([buffer_slice[0], buffer_slice[1]]) as usize;

			if message_size < 12 {
				return Err(tokio::io::Error::other("mailformed dns query response"));
			}

			if size < message_size {
				break;
			}

			let message = &mut buffer_slice[2..message_size + 2];
			let id = convert_two_u8s_to_u16_be([message[0], message[1]]);
			if let Some(addr) = waiters.lock().await.remove(&id) {
				if CONFIG.overwrite.is_some() {
					crate::ipoverwrite::overwrite_ip(message, &CONFIG.overwrite);
				}
				match addr {
					IdType::WithID(responser) => {
						responser.send_response_slice(message).await;
					}
					IdType::ZeroID(responser) => {
						[message[0], message[1]] = [0, 0];
						responser.send_response_slice(message).await;
					}
				}
			}
			buffer.remove(message_size + 2);
		}
	}
}

#[inline(always)]
async fn send_query<W: tokio::io::AsyncWrite + Unpin + Send>(
	rpipe: crate::pipe::ReceiverPipe,
	mut w: W,
	waiters: Arc<Mutex<std::collections::HashMap<u16, IdType>>>,
) -> tokio::io::Result<()> {
	loop {
		let message = crate::keepalive::pipe_recv_timeout_with(&rpipe, CONFIG.connection_keep_alive, async {
			let _ = w
				.write_all(&[0, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]) // Empty dns query
				.await;
			let _ = w.flush().await;
		})
		.await;

		if let Some(message) = message
			&& let Some(message) = rulecheck(CONFIG.rules.is_some(), &CONFIG.rules, message).await
		{
			let message_slice = message.message_slice();
			let mut id = convert_two_u8s_to_u16_be([message_slice[0], message_slice[1]]);
			let mut dq = Vec::with_capacity(message_slice.len() + 2);
			dq.extend_from_slice(&convert_u16_to_two_u8s_be(message_slice.len() as u16));
			dq.extend_from_slice(message_slice);
			if id == 0 {
				id = rand::random::<u16>();
				[dq[2], dq[3]] = convert_u16_to_two_u8s_be(id);
				waiters.lock().await.insert(id, IdType::ZeroID(message));
			} else {
				waiters.lock().await.insert(id, IdType::WithID(message));
			}
			w.write_all(&dq).await?;
			w.flush().await?;
		}
	}
}
