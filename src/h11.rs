use crate::{
	CONFIG,
	utils::{c_len, catch_in_buff},
};
use tokio::{io::AsyncWriteExt, time::sleep};

pub async fn http1(server: &crate::config::Server, rpipe: crate::pipe::ReceiverPipe) {
	// TLS Client
	let ctls = crate::tls::tlsconf(vec![b"http/1.1".to_vec()], server.disable_certificate_validation);
	let response_timeout = std::time::Duration::from_secs(CONFIG.response_timeout);
	loop {
		log::info!("{}: HTTP/1.1 connecting", server.id);
		let tls = crate::tls::dynamic_tls_conn_gen(server, &["http/1.1"], ctls.clone()).await;
		if let Err(e) = tls {
			log::warn!("{}: {e}", server.id);
			sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
			continue;
		}
		log::info!("{}: HTTP/1.1 connection established", server.id);

		let mut stream = tls.unwrap();

		let mut response_buffer = vec![0; 1024 * 128];
		let mut response_buffer: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut response_buffer);

		loop {
			let message = rpipe.recv_message().await;
			// rule check
			if let Some(message) = crate::rule::rulecheck(CONFIG.rules.is_some(), &CONFIG.rules, message).await
				&& let Err(e) = handler(
					&mut stream,
					message,
					&mut response_buffer,
					&server.hostname,
					&server.path,
					response_timeout,
					server.http_method,
				)
				.await
			{
				log::warn!("{}: {e}", server.id);
				break;
			}
		}
	}
}

async fn handler<IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
	stream: &mut IO,
	message: crate::pipe::Message,
	response_buffer: &mut tokio::io::ReadBuf<'_>,
	hostname: &str,
	path: &str,
	response_timeout: std::time::Duration,
	method: crate::config::HttpMethod,
) -> tokio::io::Result<()> {
	match method {
		crate::config::HttpMethod::GET => {
			let http_req = format!(
				"GET {path}?dns={} HTTP/1.1\r\nHost: {hostname}\r\nConnection: keep-alive\r\nAccept: application/dns-message\r\n\r\n",
				base64_url::encode(message.message_slice())
			);
			stream.write_all(http_req.as_bytes()).await?;
			stream.flush().await?;
		}
		crate::config::HttpMethod::POST => {
			let http_req = format!(
				"POST {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: keep-alive\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\ncontent-length: {}\r\n\r\n",
				message.message_slice().len()
			);
			stream.write_all(http_req.as_bytes()).await?;
			stream.write_all(message.message_slice()).await?;
			stream.flush().await?;
		}
	}

	response_buffer.clear();
	if crate::ioutils::read_buffered_timeout(response_buffer, stream, response_timeout).await? == 0 {
		return Err(tokio::io::Error::new(
			std::io::ErrorKind::UnexpectedEof,
			"connection closed unexpectedly",
		));
	}

	if let Some((heads_end, body_start)) = catch_in_buff(b"\r\n\r\n", response_buffer.filled()) {
		let content_length = c_len(&response_buffer.filled()[..heads_end]);
		if content_length == 0 {
			return Err(tokio::io::Error::other("no content-length header"));
		} else if content_length < 17 {
			return Err(tokio::io::Error::other("invalid content-length: expected >= 17 bytes"));
		} else if content_length > 65535 {
			return Err(tokio::io::Error::other(
				"invalid content-length: expected <= 65535 bytes",
			));
		}

		while response_buffer.filled()[body_start..].len() < content_length {
			if crate::ioutils::read_buffered_timeout(response_buffer, stream, response_timeout).await? == 0 {
				return Err(tokio::io::Error::new(
					std::io::ErrorKind::UnexpectedEof,
					"connection closed unexpectedly",
				));
			}
		}

		let response_body = &mut response_buffer.filled_mut()[body_start..];
		if response_body.len() > content_length {
			return Err(tokio::io::Error::other("content length exceeds"));
		}

		if CONFIG.overwrite.is_some() {
			crate::ipoverwrite::overwrite_ip(response_body, &CONFIG.overwrite);
		}
		message.send_response_slice(response_body).await;
	} else {
		return Err(tokio::io::Error::other("mailformed http response"));
	}

	Ok(())
}
