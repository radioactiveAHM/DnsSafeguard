use bytes::Bytes;
use h2::{Reason, server::SendResponse};
use http::Response;

use crate::CONFIG;

#[inline(always)]
async fn accept_stream(
	h2c: &mut h2::server::Connection<&mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>, Bytes>,
) -> tokio::io::Result<(http::Request<h2::RecvStream>, SendResponse<Bytes>)> {
	match h2c.accept().await {
		Some(Ok(stream)) => Ok(stream),
		Some(Err(e)) => Err(tokio::io::Error::other(e)),
		None => Err(tokio::io::Error::new(
			std::io::ErrorKind::ConnectionAborted,
			"connection closed",
		)),
	}
}

fn h2config(config: &crate::config::H2) -> h2::server::Builder {
	let mut builder = h2::server::Builder::new();
	builder
		.max_header_list_size(config.max_header_list_size)
		.initial_connection_window_size(config.initial_connection_window_size)
		.initial_window_size(config.initial_window_size);
	builder
}

pub async fn serve_h2(
	tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
	log: bool,
	spipe: crate::pipe::SendPipe,
) -> tokio::io::Result<()> {
	let peer_addr = tls.get_ref().0.peer_addr()?;
	let mut h2c = h2config(&CONFIG.h2)
		.handshake(tls)
		.await
		.map_err(tokio::io::Error::other)?;
	loop {
		let (mut req, mut resp) = accept_stream(&mut h2c).await?;
		log::trace!("{:?}", &req);
		match *req.method() {
			http::Method::GET => {
				if let Some(bs4dns) = req.uri().query() {
					if let Ok(dq) = base64_url::decode(&bs4dns.as_bytes()[4..]) {
						let spipe = spipe.clone();
						tokio::spawn(async move {
							if let Err(e) = handle_req(&mut resp, Bytes::from(dq), spipe).await
								&& log
							{
								log::warn!("<{}:stream(GET):{}>: {}", peer_addr, resp.stream_id().as_u32(), e);
							}
						});
					}
				} else {
					resp.send_reset(Reason::PROTOCOL_ERROR);
				}
			}
			http::Method::POST => {
				if let Some(Ok(body)) = req.body_mut().data().await {
					let spipe = spipe.clone();
					tokio::spawn(async move {
						if let Err(e) = handle_req(&mut resp, body, spipe).await
							&& log
						{
							log::warn!("<{}:stream(POST):{}>: {}", peer_addr, resp.stream_id().as_u32(), e);
						}
					});
				} else {
					resp.send_reset(Reason::PROTOCOL_ERROR);
				}
			}
			_ => {
				h2c.abrupt_shutdown(Reason::PROTOCOL_ERROR);
				return Err(tokio::io::Error::new(
					std::io::ErrorKind::ConnectionAborted,
					"invalid http method",
				));
			}
		}
	}
}

#[inline(always)]
async fn handle_req(
	resp: &mut SendResponse<Bytes>,
	body: Bytes,
	spipe: crate::pipe::SendPipe,
) -> tokio::io::Result<()> {
	let recver = spipe.send_doh_message(body).await;
	match tokio::time::timeout(
		std::time::Duration::from_secs(CONFIG.doh_server.response_timeout),
		recver,
	)
	.await
	{
		Ok(Ok(response)) => handle_resp(resp, response).await,
		Ok(Err(e)) => {
			resp.send_response(
				Response::builder()
					.version(http::Version::HTTP_2)
					.status(http::status::StatusCode::SERVICE_UNAVAILABLE)
					.body(())
					.unwrap(),
				true,
			)
			.map_err(tokio::io::Error::other)?;
			Err(tokio::io::Error::other(e))
		}
		Err(_) => {
			resp.send_response(
				Response::builder()
					.version(http::Version::HTTP_2)
					.status(http::status::StatusCode::SERVICE_UNAVAILABLE)
					.body(())
					.unwrap(),
				true,
			)
			.map_err(tokio::io::Error::other)?;
			Err(tokio::io::Error::from(tokio::io::ErrorKind::TimedOut))
		}
	}
}

struct SendResponseHeader<'a>(&'a mut SendResponse<Bytes>, http::Response<()>);
impl Future for SendResponseHeader<'_> {
	type Output = tokio::io::Result<Result<h2::SendStream<Bytes>, h2::Error>>;
	fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
		let r = self.1.clone();
		match self.0.poll_reset(cx) {
			std::task::Poll::Ready(Ok(r)) => std::task::Poll::Ready(Err(tokio::io::Error::new(
				tokio::io::ErrorKind::ConnectionAborted,
				r.description(),
			))),
			std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(tokio::io::Error::other(e))),
			std::task::Poll::Pending => std::task::Poll::Ready(Ok(self.0.send_response(r, false))),
		}
	}
}

#[inline(always)]
async fn handle_resp(rframe: &mut SendResponse<Bytes>, buf: Bytes) -> tokio::io::Result<()> {
	let heads = Response::builder()
		.version(http::Version::HTTP_2)
		.status(http::status::StatusCode::OK)
		.header("Content-Type", "application/dns-message")
		.header("Cache-Control", &CONFIG.doh_server.cache_control)
		.header("Access-Control-Allow-Origin", "*")
		.header("content-length", buf.len())
		.body(())
		.unwrap();

	if let Ok(Ok(mut bframe)) = SendResponseHeader(rframe, heads).await {
		bframe
			.send_data(Bytes::copy_from_slice(&buf), true)
			.map_err(tokio::io::Error::other)
	} else {
		Ok(())
	}
}
