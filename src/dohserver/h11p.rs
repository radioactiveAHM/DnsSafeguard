use std::fmt::Display;
use tokio::io::AsyncWriteExt;

use crate::{
	CONFIG,
	utils::{c_len, catch_in_buff},
};

pub async fn serve_http11(
	tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	spipe: crate::pipe::SendPipe,
) -> tokio::io::Result<()> {
	let mut reqbuff = [0; 1024];
	let mut reqbuff: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut reqbuff);
	loop {
		crate::ioutils::Fill(std::pin::Pin::new(tls), &mut reqbuff).await?;
		handle_req(tls, &mut reqbuff, &spipe).await?;
		reqbuff.clear();
	}
}

#[inline(always)]
async fn handle_req(
	stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	reqbuff: &mut tokio::io::ReadBuf<'_>,
	spipe: &crate::pipe::SendPipe,
) -> tokio::io::Result<()> {
	let req = HTTP11::parse(reqbuff, stream).await?;
	log::trace!("{}", String::from_utf8_lossy(reqbuff.filled()));
	let dq = match req.method {
		Method::Get(dq) => bytes::Bytes::from(dq),
		Method::Post(body_pos) => bytes::Bytes::copy_from_slice(&reqbuff.filled()[body_pos..]),
	};

	let recver = spipe.send_doh_message(dq).await;
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

#[derive(Debug)]
enum HTTP11Errors {
	NoDnsQuery,
	InvalidMethod,
	MalformedHttp,
	NoContentLength,
}
impl Display for HTTP11Errors {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			HTTP11Errors::NoDnsQuery => write!(f, "NoDnsQuery"),
			HTTP11Errors::InvalidMethod => write!(f, "InvalidMethod"),
			HTTP11Errors::MalformedHttp => write!(f, "MalformedHttp"),
			HTTP11Errors::NoContentLength => write!(f, "NoContentLength"),
		}
	}
}
impl std::error::Error for HTTP11Errors {}

enum Method {
	Get(Vec<u8>),
	Post(usize),
}
struct HTTP11 {
	method: Method,
}
impl HTTP11 {
	fn find_query(buff: &[u8]) -> Option<&[u8]> {
		let a = catch_in_buff(b"?dns=", buff)?;
		let b = catch_in_buff(b" HTTP/1.1", buff)?;
		Some(&buff[a.1..b.0])
	}
	async fn parse(
		reqbuff: &mut tokio::io::ReadBuf<'_>,
		mut stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	) -> tokio::io::Result<Self> {
		match &reqbuff.filled()[..4] {
			// _| | do not remove this space
			b"GET " => {
				if let Some(bs4dns) = HTTP11::find_query(reqbuff.filled()) {
					Ok(Self {
						method: Method::Get(
							base64_url::decode(bs4dns)
								.map_err(|_| tokio::io::Error::other("base64 url encode error"))?,
						),
					})
				} else {
					Err(tokio::io::Error::other(HTTP11Errors::NoDnsQuery))
				}
			}
			b"POST" => {
				if let Some(body_pos) = catch_in_buff(b"\r\n\r\n", reqbuff.filled()) {
					let content_length = c_len(&reqbuff.filled()[..body_pos.0]);
					if content_length == 0 {
						return Err(tokio::io::Error::other(HTTP11Errors::NoContentLength));
					}
					loop {
						if reqbuff.filled()[body_pos.1..].len() >= content_length {
							break;
						}
						crate::ioutils::read_buffered_timeout(reqbuff, &mut stream, std::time::Duration::from_secs(5))
							.await?;
					}
					Ok(Self {
						method: Method::Post(body_pos.1),
					})
				} else {
					Err(tokio::io::Error::other(HTTP11Errors::MalformedHttp))
				}
			}
			_ => Err(tokio::io::Error::other(HTTP11Errors::InvalidMethod)),
		}
	}
}
