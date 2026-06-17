use bytes::Bytes;
use h2::{Reason, server::SendResponse};
use http::Response;

use crate::CONFIG;

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
	log_err: bool,
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

		let spipe = spipe.clone();
		match *req.method() {
			http::Method::GET => {
				tokio::spawn(async move {
					match get_method(req) {
						Ok(dq) => {
							if let Err(e) = handle_req(&mut resp, dq, spipe).await
								&& log_err
							{
								log::warn!("<{}:stream(GET):{}>: {}", peer_addr, resp.stream_id().as_u32(), e);
							}
						}
						Err(e) => {
							if log_err {
								log::warn!("<{}:stream(GET):{}>: {}", peer_addr, resp.stream_id().as_u32(), e);
							}
							resp.send_reset(Reason::PROTOCOL_ERROR);
						}
					}
				});
			}
			http::Method::POST => {
				tokio::spawn(async move {
					match recv_post_bytes(&mut req).await {
						Ok(body) => {
							if let Err(e) = handle_req(&mut resp, body, spipe).await {
								if log_err {
									log::warn!("<{}:stream(POST):{}>: {}", peer_addr, resp.stream_id().as_u32(), e);
								}
								resp.send_reset(Reason::PROTOCOL_ERROR);
							}
						}
						Err(e) => {
							if log_err {
								log::warn!("<{}:stream(POST):{}>: {}", peer_addr, resp.stream_id().as_u32(), e);
							}
							resp.send_reset(Reason::PROTOCOL_ERROR);
						}
					}
				});
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

async fn recv_post_bytes(recv: &mut http::Request<h2::RecvStream>) -> tokio::io::Result<Bytes> {
	let content_length = recv
		.headers()
		.get("content-length")
		.ok_or(tokio::io::Error::other("no content length"))?
		.to_str()
		.map_err(tokio::io::Error::other)?
		.parse::<usize>()
		.map_err(tokio::io::Error::other)?;

	if content_length < 17 {
		return Err(tokio::io::Error::other("invalid content-length: expected >= 17 bytes"));
	} else if content_length > 65535 {
		return Err(tokio::io::Error::other(
			"invalid content-length: expected <= 65535 bytes",
		));
	}

	// TODO: handle multi data frame buffering, first check if required
	recv.body_mut()
		.data()
		.await
		.ok_or(tokio::io::Error::new(
			std::io::ErrorKind::UnexpectedEof,
			"connection closed unexpectedly",
		))?
		.map_err(tokio::io::Error::other)
}

fn get_method(http_request: http::Request<h2::RecvStream>) -> tokio::io::Result<Bytes> {
	let http_query = http_request
		.uri()
		.query()
		.ok_or(tokio::io::Error::other("none http queery"))?;
	if http_query.contains("dns=") {
		if http_query.as_bytes()[4..].is_empty() {
			return Err(tokio::io::Error::other("invalid http dns queery"));
		}
		let dns_query = base64_url::decode(&http_query.as_bytes()[4..])
			.map_err(|_| tokio::io::Error::other("decode http query failed"))?;
		if dns_query.len() < 17 {
			return Err(tokio::io::Error::other("invalid query: expected >= 17 bytes"));
		} else if dns_query.len() > 65535 {
			return Err(tokio::io::Error::other("invalid query: expected <= 65535 bytes"));
		}

		Ok(Bytes::from(dns_query))
	} else {
		Err(tokio::io::Error::other("none http dns queery"))
	}
}

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

async fn handle_resp(rframe: &mut SendResponse<Bytes>, buf: Bytes) -> tokio::io::Result<()> {
	let http_response = Response::builder()
		.version(http::Version::HTTP_2)
		.status(http::status::StatusCode::OK)
		.header("Content-Type", "application/dns-message")
		.header("Cache-Control", &CONFIG.doh_server.cache_control)
		.header("Access-Control-Allow-Origin", "*")
		.header("content-length", buf.len())
		.body(())
		.unwrap();

	if let Ok(mut bframe) = rframe.send_response(http_response, false) {
		bframe.send_data(buf, true).map_err(tokio::io::Error::other)?;
	}

	Ok(())
}
