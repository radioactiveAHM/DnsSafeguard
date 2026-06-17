use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
	CONFIG,
	utils::{c_len, catch_in_buff},
};

pub async fn serve_http11(
	tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	spipe: crate::pipe::SendPipe,
) -> tokio::io::Result<()> {
	let mut reqbuff = vec![0; 1024 * 128];
	let mut reqbuff: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut reqbuff);
	loop {
		reqbuff.clear();
		if let Ok(n) = tls.read_buf(&mut reqbuff).await {
			if n == 0 {
				// connection closed
				return Ok(());
			}
			handle_req(tls, &mut reqbuff, &spipe).await?;
		}
	}
}

async fn handle_req(
	stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	reqbuff: &mut tokio::io::ReadBuf<'_>,
	spipe: &crate::pipe::SendPipe,
) -> tokio::io::Result<()> {
	let recver = spipe.send_doh_message(parse(reqbuff, stream).await?).await;
	match tokio::time::timeout(
		std::time::Duration::from_secs(CONFIG.doh_server.response_timeout),
		recver,
	)
	.await
	{
		Ok(Ok(response)) => {
			stream
				.write_all(
					format!(
						"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nCache-Control: {}\r\nAccess-Control-Allow-Origin: *\r\ncontent-length: {}\r\n\r\n",
						&CONFIG.doh_server.cache_control,
						response.len()
					)
					.as_bytes(),
				)
				.await?;
			stream.write_all(&response).await
		}
		Ok(Err(e)) => {
			stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").await?;
			Err(tokio::io::Error::other(e))
		}
		Err(_) => {
			stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").await?;
			Err(tokio::io::Error::from(tokio::io::ErrorKind::TimedOut))
		}
	}
}

fn find_query(buff: &[u8]) -> Option<&[u8]> {
	let a = catch_in_buff(b"?dns=", buff)?;
	let b = catch_in_buff(b" HTTP/1.1", buff)?;
	if a.1 == b.0 {
		return None;
	}
	Some(&buff[a.1..b.0])
}
async fn parse(
	reqbuff: &mut tokio::io::ReadBuf<'_>,
	mut stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> tokio::io::Result<bytes::Bytes> {
	match &reqbuff.filled()[..4] {
		// _| | do not remove this space
		b"GET " => {
			// recv full request with body
			loop {
				let size = reqbuff.filled().len();
				if reqbuff.filled()[size - 4..] == *b"\r\n\r\n" {
					break;
				}
				let n = crate::ioutils::read_buffered_timeout(reqbuff, &mut stream, std::time::Duration::from_secs(2))
					.await?;
				if n == 0 {
					return Err(tokio::io::Error::new(
						std::io::ErrorKind::UnexpectedEof,
						"connection closed unexpectedly",
					));
				}
			}

			if let Some(bs4dns) = find_query(reqbuff.filled()) {
				let dq = base64_url::decode(bs4dns).map_err(|_| tokio::io::Error::other("base64 url encode error"))?;
				if dq.len() < 17 {
					return Err(tokio::io::Error::other("invalid query: expected >= 17 bytes"));
				} else if dq.len() > 65535 {
					return Err(tokio::io::Error::other("invalid query: expected <= 65535 bytes"));
				}

				Ok(bytes::Bytes::from(dq))
			} else {
				Err(tokio::io::Error::other("malformed http request"))
			}
		}
		b"POST" => {
			if let Some(body_pos) = catch_in_buff(b"\r\n\r\n", reqbuff.filled()) {
				let content_length = c_len(&reqbuff.filled()[..body_pos.0]);
				if content_length == 0 {
					return Err(tokio::io::Error::other("no content length"));
				} else if content_length < 17 {
					return Err(tokio::io::Error::other("invalid content-length: expected >= 17 bytes"));
				} else if content_length > 65535 {
					return Err(tokio::io::Error::other(
						"invalid content-length: expected <= 65535 bytes",
					));
				}

				while reqbuff.filled()[body_pos.1..].len() < content_length {
					if crate::ioutils::read_buffered_timeout(reqbuff, &mut stream, std::time::Duration::from_secs(2))
						.await? == 0
					{
						return Err(tokio::io::Error::new(
							std::io::ErrorKind::UnexpectedEof,
							"connection closed unexpectedly",
						));
					}
				}

				let response_body = &reqbuff.filled()[body_pos.1..];
				if response_body.len() > content_length {
					return Err(tokio::io::Error::other("content length exceeds"));
				}

				Ok(bytes::Bytes::copy_from_slice(response_body))
			} else {
				Err(tokio::io::Error::other("malformed http request"))
			}
		}
		_ => Err(tokio::io::Error::other("invalid http method")),
	}
}
