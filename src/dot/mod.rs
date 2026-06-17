use crate::{
	CONFIG,
	rule::rulecheck,
	tls,
	utils::{convert_two_u8s_to_u16_be, convert_u16_to_two_u8s_be},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Query {
	id: u16,
	message: crate::pipe::Message,
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

		let waiters: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u16, Query>>> =
			std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

		let waiters2 = waiters.clone();
		let rpipe = rpipe.clone();

		let (mut recv_task, mut send_task) = (
			tokio::spawn(recv_query(r, waiters2)),
			tokio::spawn(send_query(rpipe, w, waiters)),
		);
		let res = tokio::select! {
			res = &mut recv_task => {
				res
			}
			res = &mut send_task => {
				res
			}
		};
		match res {
			Ok(Err(e)) => log::warn!("{}: {e}", server.id),
			Err(e) => log::warn!("{}: {e}", server.id),
			_ => log::warn!("{}: connection closed", server.id),
		}

		recv_task.abort();
		send_task.abort();
	}
}

async fn recv_query<R: tokio::io::AsyncRead + Unpin>(
	mut r: R,
	waiters: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u16, Query>>>,
) -> tokio::io::Result<()> {
	let mut buffer = crate::utils::DeqBuffer::new(1024 * 8);
	let mut reading_buf = [0u8; 1024 * 8];
	let mut reading_buf_rb = tokio::io::ReadBuf::new(&mut reading_buf);
	loop {
		reading_buf_rb.clear();
		r.read_buf(&mut reading_buf_rb).await?;
		if reading_buf_rb.filled().is_empty() {
			return Err(tokio::io::Error::new(
				std::io::ErrorKind::UnexpectedEof,
				"connection eof",
			));
		}

		buffer.write(reading_buf_rb.filled());
		loop {
			let buffer_slice = buffer.slice();
			let size = buffer_slice.len();
			if size < 17 {
				break;
			} else if size > 65537 {
				return Err(tokio::io::Error::other("buffer overflow"));
			}

			let message_size = convert_two_u8s_to_u16_be([buffer_slice[0], buffer_slice[1]]) as usize;

			if message_size < 17 {
				return Err(tokio::io::Error::other("invalid query size: expected >= 17 bytes"));
			} else if message_size > 65535 {
				return Err(tokio::io::Error::other("invalid query size: expected <= 65535 bytes"));
			}

			if size < message_size {
				break;
			}

			let message = &mut buffer_slice[2..message_size + 2];
			let id = convert_two_u8s_to_u16_be([message[0], message[1]]);
			if let Some(query) = waiters.lock().await.remove(&id) {
				if CONFIG.overwrite.is_some() {
					crate::ipoverwrite::overwrite_ip(message, &CONFIG.overwrite);
				}
				[message[0], message[1]] = convert_u16_to_two_u8s_be(query.id);
				query.message.send_response_slice(message).await;
			}
			buffer.remove(message_size + 2);
		}
	}
}

async fn send_query<W: tokio::io::AsyncWrite + Unpin + Send>(
	rpipe: crate::pipe::ReceiverPipe,
	mut w: W,
	waiters: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u16, Query>>>,
) -> tokio::io::Result<()> {
	loop {
		let message = crate::keepalive::pipe_recv_timeout_with(&rpipe, CONFIG.connection_keep_alive, async {
			w.write_all(&[0, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]) // Empty dns query
				.await?;
			w.flush().await
		})
		.await?;

		if let Some(message) = message
			&& let Some(message) = rulecheck(CONFIG.rules.is_some(), &CONFIG.rules, message).await
		{
			let message_slice = message.message_slice();
			let id = convert_two_u8s_to_u16_be([message_slice[0], message_slice[1]]);
			let mut dq = Vec::with_capacity(message_slice.len() + 2);
			dq.extend_from_slice(&convert_u16_to_two_u8s_be(message_slice.len() as u16));
			dq.extend_from_slice(message_slice);
			let query = Query { id, message };
			// guarantee unique id
			let unique_id = {
				let mut id: u16;
				loop {
					id = rand::random::<u16>();
					if !waiters.lock().await.contains_key(&id) {
						break;
					}
				}
				id
			};
			[dq[2], dq[3]] = convert_u16_to_two_u8s_be(unique_id);
			waiters.lock().await.insert(unique_id, query);
			w.write_all(&dq).await?;
			w.flush().await?;
		}
	}
}
