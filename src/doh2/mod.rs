use crate::{CONFIG, config, rule::rulecheck, tls};
use core::str;
use h2::client::SendRequest;
use std::{net::SocketAddr, sync::Arc};
use tokio::time::sleep;

fn h2config(config: &config::H2) -> h2::client::Builder {
	let mut builder = h2::client::Builder::new();
	builder
		.header_table_size(config.header_table_size)
		.max_header_list_size(config.max_header_list_size)
		.initial_connection_window_size(config.initial_connection_window_size)
		.initial_window_size(config.initial_window_size);
	builder
}

pub async fn http2() {
	// TLS Conf
	let h2tls = tls::tlsconf(vec![b"h2".to_vec()], CONFIG.disable_certificate_validation);
	let builder = h2config(&CONFIG.h2);

	let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());

	let mut tank: Option<(Box<[u8; 512]>, usize, SocketAddr)> = None;
	let disconnected = crate::disconnected::Disconnected::new();

	loop {
		log::info!("H2 connecting");
		let tls = crate::tls::dynamic_tls_conn_gen(&["h2"], h2tls.clone()).await;
		if tls.is_err() {
			log::warn!("{}", tls.unwrap_err());
			sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
			continue;
		}

		let (client, mut h2c) = builder.handshake(tls.unwrap()).await.unwrap();
		let mut pinger = h2c.ping_pong().unwrap();
		log::info!("H2 connection established");

		disconnected.connect();
		let _disconnected = disconnected.clone();
		let watcher = tokio::spawn(async move {
			if let Err(e) = h2c.await {
				_disconnected.disconnect();
				log::warn!("{e}");
			}
		});

		if let Some((dns_query, query_size, addr)) = tank {
			let udp = udp.clone();
			let client = client.clone();
			tokio::spawn(async move {
				if let Err(e) = send_req((*dns_query, query_size), client, addr, udp).await {
					log::warn!("{e}");
				}
			});
			tank = None;
		}

		let mut dns_query = [0u8; 512];
		loop {
			let udp = udp.clone();
			if disconnected.get() {
				watcher.abort();
				break;
			}

			let message =
				crate::keepalive::recv_timeout_with(&udp, CONFIG.connection_keep_alive, &mut dns_query, async {
					match tokio::time::timeout(
						std::time::Duration::from_secs(CONFIG.response_timeout),
						pinger.ping(h2::Ping::opaque()),
					)
					.await
					{
						Err(_) | Ok(Err(_)) => {
							disconnected.disconnect();
							log::warn!("timeout/error waiting for pong");
						}
						_ => (),
					};
				})
				.await;

			if let Some(Ok((query_size, addr))) = message {
				if (CONFIG.rules.is_some()
					&& rulecheck(&CONFIG.rules, &mut dns_query[..query_size], addr, udp.clone()).await)
					|| query_size < 12
				{
					continue;
				}

				if disconnected.get() {
					tank = Some((Box::new(dns_query), query_size, addr));
					watcher.abort();
					break;
				}

				match client.clone().ready().await {
					Ok(client) => {
						tokio::spawn(async move {
							if let Err(e) = send_req((dns_query, query_size), client, addr, udp).await {
								log::warn!("{e}");
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

async fn send_req(
	dns_query: ([u8; 512], usize),
	mut h2_client: SendRequest<bytes::Bytes>,
	addr: SocketAddr,
	udp: Arc<tokio::net::UdpSocket>,
) -> tokio::io::Result<()> {
	let path = if let Some(path) = &CONFIG.custom_http_path {
		path.as_str()
	} else {
		"/dns-query"
	};
	let mut resp = match CONFIG.http_method {
		config::HttpMethod::GET => get(&mut h2_client, &CONFIG.server_name, path, &dns_query.0[..dns_query.1]).await?,
		config::HttpMethod::POST => {
			post(&mut h2_client, &CONFIG.server_name, path, &dns_query.0[..dns_query.1]).await?
		}
	};

	if resp.status() == http::status::StatusCode::OK {
		let clen: usize = if let Some(clen) = resp.headers().get("content-length")
			&& let Ok(clen) = clen.to_str()
		{
			clen.parse().unwrap_or(0)
		} else {
			0
		};

		let mut buf = [0; 1024 * 8];
		let mut buf_rb = tokio::io::ReadBuf::new(&mut buf);
		loop {
			if let Some(body) = resp.body_mut().data().await {
				buf_rb.put_slice(&body.map_err(tokio::io::Error::other)?);
			}
			if clen == 0 {
				// if no content-length provided we read only once
				break;
			}
			if buf_rb.filled().len() >= clen {
				break;
			}
		}

		if CONFIG.overwrite.is_some() {
			crate::ipoverwrite::overwrite_ip(buf_rb.filled_mut(), &CONFIG.overwrite);
		}

		let _ = udp.send_to(buf_rb.filled(), addr).await;
	} else {
		log::warn!("remote responded with status code of {}", resp.status().as_str());
	}

	Ok(())
}

#[inline(always)]
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
					.path_and_query(format!("{}?dns={}", path, base64_url::encode(dns_query)))
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

#[inline(always)]
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
