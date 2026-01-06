mod noise;
pub mod qtls;
pub mod transporter;

use core::str;
use std::{net::SocketAddr, sync::Arc};

use tokio::time::{sleep, timeout};

use bytes::BufMut;
use h3::client::SendRequest;

use crate::{
	CONFIG,
	config::{self, Noise},
	rule::rulecheck,
};

pub async fn quic_setup(
	target: SocketAddr,
	noise: &Noise,
	quic_conf_file: &crate::config::Quic,
	alpn: &str,
	network_interface: &Option<String>,
) -> quinn::Endpoint {
	let udp = std::net::UdpSocket::bind(crate::udp::udp_addr_to_bind(network_interface, target.is_ipv4())).unwrap();

	if noise.enable {
		noise::noiser(noise, target, &udp);
	}

	let mut endpoint = quinn::Endpoint::new(
		quinn::EndpointConfig::default(),
		None,
		udp,
		Arc::new(quinn::TokioRuntime),
	)
	.unwrap();

	let mut qc = quinn::ClientConfig::new(qtls::qtls(alpn));
	qc.transport_config(transporter::tc(quic_conf_file));
	endpoint.set_default_client_config(qc);

	endpoint
}

pub async fn http3() {
	let mut endpoint = quic_setup(
		CONFIG.remote_addrs,
		&CONFIG.noise,
		&CONFIG.quic,
		"h3",
		&CONFIG.interface,
	)
	.await;

	let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());

	let mut tank: Option<(Vec<u8>, SocketAddr)> = None;
	let disconnected = crate::disconnected::Disconnected::new();

	let mut connecting_retry = 0u8;
	loop {
		if connecting_retry == 3 {
			connecting_retry = 0;
			endpoint = quic_setup(
				CONFIG.remote_addrs,
				&CONFIG.noise,
				&CONFIG.quic,
				"h3",
				&CONFIG.interface,
			)
			.await;
		}
		log::info!("H3 connecting");
		// Connect to dns server
		let connecting = endpoint.connect(CONFIG.remote_addrs, &CONFIG.server_name).unwrap();

		let conn = {
			let timing = timeout(std::time::Duration::from_secs(CONFIG.quic.connecting_timeout), async {
				let connecting = connecting.into_0rtt();
				if let Ok((conn, rtt)) = connecting {
					rtt.await;
					log::info!("H3 0RTT connection established");
					Ok(conn)
				} else {
					let conn = endpoint
						.connect(CONFIG.remote_addrs, &CONFIG.server_name)
						.unwrap()
						.await;
					if conn.is_ok() {
						log::info!("H3 connection established");
					}
					conn
				}
			})
			.await;

			if let Ok(pending) = timing {
				pending
			} else {
				connecting_retry += 1;
				log::warn!("connecting timeout");
				sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
				continue;
			}
		};

		if conn.is_err() {
			connecting_retry += 1;
			log::warn!("{}", conn.unwrap_err());
			sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
			continue;
		}
		connecting_retry = 0;

		let (mut h3c, h3) = match h3::client::new(h3_quinn::Connection::new(conn.unwrap())).await {
			Ok(conn) => conn,
			Err(e) => {
				log::warn!("{e}");
				continue;
			}
		};

		disconnected.connect();
		let _disconnected = disconnected.clone();
		let watcher = tokio::spawn(async move {
			log::warn!("{}", h3c.wait_idle().await);
			_disconnected.disconnect();
		});

		if let Some((dns_query, addr)) = tank {
			let udp = udp.clone();
			let h3 = h3.clone();
			tokio::spawn(async move {
				if let Err(e) = send_request(h3, dns_query, addr, udp).await {
					log::warn!("{e}");
				}
			});
			tank = None;
		}

		let mut dns_query = [0u8; 512];
		loop {
			let disconnected = disconnected.clone();
			let udp = udp.clone();
			if disconnected.get() {
				watcher.abort();
				break;
			}

			let message =
				crate::keepalive::recv_timeout_with(&udp, CONFIG.connection_keep_alive, &mut dns_query, async {
					match tokio::time::timeout(
						std::time::Duration::from_secs(CONFIG.response_timeout),
						h3.clone().send_request(
							http::Request::get(format!("https://{}/", CONFIG.server_name.as_str()))
								.body(())
								.unwrap(),
						),
					)
					.await
					{
						Err(_) | Ok(Err(_)) => {
							disconnected.disconnect();
							log::warn!("timeout/error waiting for keep-alive response");
						}
						_ => (),
					};
				})
				.await;

			if let Some(Ok((query_size, addr))) = message {
				// rule check
				if (CONFIG.rules.is_some()
					&& rulecheck(&CONFIG.rules, &mut dns_query[..query_size], addr, udp.clone()).await)
					|| query_size < 12
				{
					continue;
				}

				if disconnected.get() {
					tank = Some((dns_query[..query_size].to_vec(), addr));
					watcher.abort();
					break;
				}

				let h3 = h3.clone();
				tokio::spawn(async move {
					if let Err(e) = send_request(h3, dns_query[..query_size].to_vec(), addr, udp).await {
						log::warn!("{e}");
						if e.kind() == std::io::ErrorKind::TimedOut {
							disconnected.disconnect();
						}
					}
				});
			}
		}
	}
}

#[inline(always)]
async fn send_request(
	mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
	dns_query: Vec<u8>,
	addr: SocketAddr,
	udp: Arc<tokio::net::UdpSocket>,
) -> tokio::io::Result<()> {
	let path = if let Some(path) = &CONFIG.custom_http_path {
		path.as_str()
	} else {
		"/dns-query"
	};
	let mut reqs = match CONFIG.http_method {
		config::HttpMethod::GET => get(&mut h3, &CONFIG.server_name, path, dns_query).await?,
		config::HttpMethod::POST => post(&mut h3, &CONFIG.server_name, path, dns_query).await?,
	};

	reqs.finish().await.map_err(tokio::io::Error::other)?;

	let resp = timeout(
		std::time::Duration::from_secs(CONFIG.response_timeout),
		reqs.recv_response(),
	)
	.await?
	.map_err(tokio::io::Error::other)?;

	if resp.status() == http::status::StatusCode::OK {
		let clen: usize = if let Some(clen) = resp.headers().get("content-length")
			&& let Ok(clen) = clen.to_str()
		{
			clen.parse().unwrap_or(0)
		} else {
			0
		};

		let timeout_dur = std::time::Duration::from_secs(CONFIG.response_timeout);
		let mut data = bytes::BytesMut::from(downcast(
			timeout(timeout_dur, reqs.recv_data())
				.await?
				.map_err(tokio::io::Error::other)?
				.ok_or(tokio::io::Error::other("stream closed without data"))?,
		));
		loop {
			if clen == 0 || data.len() >= clen {
				// if no content-length provided we read only once
				break;
			}
			data.put(
				timeout(timeout_dur, reqs.recv_data())
					.await?
					.map_err(tokio::io::Error::other)?
					.ok_or(tokio::io::Error::other("stream closed with incomplete data"))?,
			);
		}

		if CONFIG.overwrite.is_some() {
			crate::ipoverwrite::overwrite_ip(&mut data, &CONFIG.overwrite);
		}
		let _ = udp.send_to(&data, addr).await;
	} else {
		log::warn!("remote responded with status code of {}", resp.status().as_str());
	}

	Ok(())
}

#[inline(always)]
fn downcast(buf: impl std::any::Any + 'static) -> bytes::Bytes {
	let boxed: Box<dyn std::any::Any> = Box::new(buf);
	boxed.downcast::<bytes::Bytes>().ok().map(|b| *b).unwrap()
}

#[inline(always)]
async fn get(
	h3: &mut SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
	server_name: &str,
	path: &str,
	dns_query: Vec<u8>,
) -> tokio::io::Result<h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>> {
	h3.send_request(
		http::Request::get(
			http::Uri::builder()
				.scheme("https")
				.authority(server_name)
				.path_and_query(format!("{}?dns={}", path, base64_url::encode(&dns_query)))
				.build()
				.map_err(tokio::io::Error::other)?,
		)
		.version(http::Version::HTTP_3)
		.header("Accept", "application/dns-message")
		.body(())
		.map_err(tokio::io::Error::other)?,
	)
	.await
	.map_err(tokio::io::Error::other)
}

#[inline(always)]
async fn post(
	h3: &mut SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
	server_name: &str,
	path: &str,
	dns_query: Vec<u8>,
) -> tokio::io::Result<h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>> {
	let mut pending = h3
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
			.version(http::Version::HTTP_3)
			.body(())
			.map_err(tokio::io::Error::other)?,
		)
		.await
		.map_err(tokio::io::Error::other)?;

	pending
		.send_data(bytes::Bytes::copy_from_slice(&dns_query))
		.await
		.map_err(tokio::io::Error::other)?;
	Ok(pending)
}
