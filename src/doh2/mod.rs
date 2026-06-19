use crate::{CONFIG, config, rule::rulecheck};
use bytes::BufMut;
use core::str;
use h2::client::SendRequest;
use tokio::time::sleep;

fn h2config(config: &config::H2) -> h2::client::Builder {
	let mut builder = h2::client::Builder::new();
	builder
		.header_table_size(config.header_table_size)
		.max_header_list_size(config.max_header_list_size)
		.initial_connection_window_size(config.initial_connection_window_size)
		.initial_window_size(config.initial_window_size)
		.max_pending_accept_reset_streams(config.max_pending_accept_reset_streams)
		.max_concurrent_reset_streams(config.max_concurrent_reset_streams)
		.max_frame_size(config.max_frame_size);
	builder
}

pub async fn http2(server: &'static crate::config::Server, rpipe: crate::pipe::ReceiverPipe) {
	let builder = h2config(&CONFIG.h2);

	let mut tank: Option<crate::pipe::Message> = None;
	let disconnected = crate::disconnected::Disconnected::new();

	let response_timeout = std::time::Duration::from_secs(CONFIG.response_timeout);

	loop {
		log::info!("{}: H2 connecting", server.id);
		let tls = match crate::tls::dynamic_tls_conn_gen(server, &["h2"]).await {
			Some(tls) => tls,
			None => {
				sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
				continue;
			}
		};

		let (client, mut h2c) = builder.handshake(tls).await.unwrap();
		let mut pinger = h2c.ping_pong().unwrap();
		log::info!("{}: H2 connection established", server.id);

		disconnected.connect();
		let _disconnected = disconnected.clone();
		let watcher = tokio::spawn(async move {
			if let Err(e) = h2c.await {
				_disconnected.disconnect();
				log::warn!("{}: {e}", server.id);
			}
		});

		if let Some(message) = tank {
			let client = client.clone();
			tokio::spawn(async move {
				if let Err(e) = send_req(
					message,
					client,
					&server.hostname,
					&server.path,
					&server.http_method,
					response_timeout,
				)
				.await
				{
					log::warn!("{}: {e}", server.id);
				}
			});
			tank = None;
		}

		loop {
			if disconnected.get() {
				watcher.abort();
				break;
			}

			let message = crate::keepalive::pipe_recv_timeout_with(&rpipe, CONFIG.connection_keep_alive, async {
				if let Err(e) = tokio::time::timeout(
					std::time::Duration::from_secs(CONFIG.response_timeout),
					pinger.ping(h2::Ping::opaque()),
				)
				.await?
				{
					Err(tokio::io::Error::other(e))
				} else {
					Ok(())
				}
			})
			.await;

			match message {
				Ok(Some(message)) => {
					if let Some(message) = rulecheck(CONFIG.rules.is_some(), &CONFIG.rules, message).await {
						if disconnected.get() {
							tank = Some(message);
							watcher.abort();
							break;
						}

						match client.clone().ready().await {
							Ok(client) => {
								tokio::spawn(async move {
									if let Err(e) = send_req(
										message,
										client,
										&server.hostname,
										&server.path,
										&server.http_method,
										response_timeout,
									)
									.await
									{
										log::warn!("{}: {e}", server.id);
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
				Err(e) => {
					disconnected.disconnect();
					log::warn!("{}: keepalive({e})", server.id);
				}
				_ => (),
			}
		}
	}
}

async fn send_req(
	message: crate::pipe::Message,
	mut h2_client: SendRequest<bytes::Bytes>,
	hostname: &str,
	path: &str,
	http_method: &config::HttpMethod,
	response_timeout: std::time::Duration,
) -> tokio::io::Result<()> {
	let mut resp = match http_method {
		config::HttpMethod::GET => get(&mut h2_client, hostname, path, message.message_slice()).await?,
		config::HttpMethod::POST => post(&mut h2_client, hostname, path, message.message_slice()).await?,
	};

	if resp.status() == http::status::StatusCode::OK {
		let content_length: usize = resp
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

		let mut data = bytes::BytesMut::from(
			tokio::time::timeout(response_timeout, resp.body_mut().data())
				.await?
				.ok_or(tokio::io::Error::other("stream closed without data"))?
				.map_err(tokio::io::Error::other)?,
		);
		while data.len() < content_length {
			data.put(
				tokio::time::timeout(response_timeout, resp.body_mut().data())
					.await?
					.ok_or(tokio::io::Error::other("stream closed with incomplete data"))?
					.map_err(tokio::io::Error::other)?,
			);
		}

		if data.len() > content_length {
			return Err(tokio::io::Error::other("content length exceeds"));
		}

		if CONFIG.overwrite.is_some() {
			crate::ipoverwrite::overwrite_ip(&mut data, &CONFIG.overwrite);
		}

		message.send_response(data.freeze()).await;
	} else {
		log::warn!("remote responded with status code of {}", resp.status().as_str());
	}

	Ok(())
}

async fn get(
	h2_client: &mut SendRequest<bytes::Bytes>,
	server_name: &str,
	path: &str,
	dns_query: &[u8],
) -> tokio::io::Result<http::Response<h2::RecvStream>> {
	h2_client
		.send_request(
			http::Request::get(
				http::Uri::builder()
					.scheme("https")
					.authority(server_name)
					.path_and_query(format!("{}?dns={}", path, base64_url::encode(&dns_query)))
					.build()
					.map_err(tokio::io::Error::other)?,
			)
			.version(http::Version::HTTP_2)
			.header("Accept", "application/dns-message")
			.body(())
			.map_err(tokio::io::Error::other)?,
			true,
		)
		.map_err(tokio::io::Error::other)?
		.0
		.await
		.map_err(tokio::io::Error::other)
}

async fn post(
	h2_client: &mut SendRequest<bytes::Bytes>,
	server_name: &str,
	path: &str,
	dns_query: &[u8],
) -> tokio::io::Result<http::Response<h2::RecvStream>> {
	let mut p = h2_client
		.send_request(
			http::Request::post(
				http::Uri::builder()
					.scheme("https")
					.authority(server_name)
					.path_and_query(path)
					.build()
					.map_err(tokio::io::Error::other)?,
			)
			.header("Accept", "application/dns-message")
			.header("Content-Type", "application/dns-message")
			.header("content-length", dns_query.len())
			.version(http::Version::HTTP_2)
			.body(())
			.map_err(tokio::io::Error::other)?,
			false,
		)
		.map_err(tokio::io::Error::other)?;
	p.1.send_data(bytes::Bytes::copy_from_slice(dns_query), true)
		.map_err(tokio::io::Error::other)?;
	p.0.await.map_err(tokio::io::Error::other)
}
