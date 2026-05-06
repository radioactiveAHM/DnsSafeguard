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
	config::{self, Noiser},
	rule::rulecheck,
};

pub async fn quic_setup(
	target: SocketAddr,
	noiser: &Noiser,
	quic_conf_file: &crate::config::Quic,
	alpn: &str,
	network_interface: &Option<String>,
) -> quinn::Endpoint {
	let udp = std::net::UdpSocket::bind(crate::udp::udp_addr_to_bind(network_interface, target.is_ipv4())).unwrap();

	if noiser.enable {
		noise::noiser(&noiser.noises, target, &udp);
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

pub async fn http3(server: &'static crate::config::Server, rpipe: crate::pipe::ReceiverPipe) {
	let mut endpoint = quic_setup(
		server.remote_addrs,
		&CONFIG.noiser,
		&CONFIG.quic,
		"h3",
		&CONFIG.interface,
	)
	.await;

	let mut tank: Option<crate::pipe::Message> = None;
	let disconnected = crate::disconnected::Disconnected::new();

	let mut connecting_retry = 0u8;
	loop {
		if connecting_retry == 3 {
			connecting_retry = 0;
			endpoint = quic_setup(
				server.remote_addrs,
				&CONFIG.noiser,
				&CONFIG.quic,
				"h3",
				&CONFIG.interface,
			)
			.await;
		}
		log::info!("{}: H3 connecting", server.id);
		// Connect to dns server
		let connecting = endpoint.connect(server.remote_addrs, &server.sni).unwrap();

		let conn = {
			let timing = timeout(std::time::Duration::from_secs(CONFIG.quic.connecting_timeout), async {
				let connecting = connecting.into_0rtt();
				if let Ok((conn, rtt)) = connecting {
					rtt.await;
					log::info!("{}: H3 0RTT connection established", server.id);
					Ok(conn)
				} else {
					let conn = endpoint.connect(server.remote_addrs, &server.sni).unwrap().await;
					if conn.is_ok() {
						log::info!("{}: H3 connection established", server.id);
					}
					conn
				}
			})
			.await;

			if let Ok(pending) = timing {
				pending
			} else {
				connecting_retry += 1;
				log::warn!("{}: connecting timeout", server.id);
				sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
				continue;
			}
		};

		if let Err(e) = conn {
			log::warn!("{}: {e}", server.id);
			connecting_retry += 1;
			sleep(std::time::Duration::from_secs(CONFIG.reconnect_sleep)).await;
			continue;
		}
		connecting_retry = 0;

		let (mut h3c, h3) = match h3::client::new(h3_quinn::Connection::new(conn.unwrap())).await {
			Ok(conn) => conn,
			Err(e) => {
				log::warn!("{}: {e}", server.id);
				continue;
			}
		};

		disconnected.connect();
		let _disconnected = disconnected.clone();
		let watcher = tokio::spawn(async move {
			log::warn!("{}: {}", server.id, h3c.wait_idle().await);
			_disconnected.disconnect();
		});

		if let Some(message) = tank {
			let h3 = h3.clone();
			tokio::spawn(async move {
				if let Err(e) = send_request(
					message,
					h3,
					&server.hostname,
					&server.custom_http_path,
					&server.http_method,
				)
				.await
				{
					log::warn!("{}: {e}", server.id);
				}
			});
			tank = None;
		}

		loop {
			let disconnected = disconnected.clone();
			if disconnected.get() {
				watcher.abort();
				break;
			}

			let message = crate::keepalive::pipe_recv_timeout_with(&rpipe, CONFIG.connection_keep_alive, async {
				match tokio::time::timeout(
					std::time::Duration::from_secs(CONFIG.response_timeout),
					h3.clone().send_request(
						http::Request::get(format!("https://{}/", server.hostname.as_str()))
							.body(())
							.unwrap(),
					),
				)
				.await
				{
					Err(_) | Ok(Err(_)) => {
						disconnected.disconnect();
						log::warn!("{}: timeout/error waiting for keep-alive response", server.id);
					}
					_ => (),
				};
			})
			.await;

			if let Some(message) = message
				&& let Some(message) = rulecheck(CONFIG.rules.is_some(), &CONFIG.rules, message).await
			{
				if disconnected.get() {
					tank = Some(message);
					watcher.abort();
					break;
				}

				let h3 = h3.clone();
				tokio::spawn(async move {
					if let Err(e) = send_request(
						message,
						h3,
						&server.hostname,
						&server.custom_http_path,
						&server.http_method,
					)
					.await
					{
						log::warn!("{}: {e}", server.id);
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
	message: crate::pipe::Message,
	mut h3: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
	hostname: &str,
	custom_http_path: &Option<String>,
	http_method: &config::HttpMethod,
) -> tokio::io::Result<()> {
	let path = if let Some(path) = custom_http_path {
		path.as_str()
	} else {
		"/dns-query"
	};
	let mut reqs = match http_method {
		config::HttpMethod::GET => get(&mut h3, hostname, path, message.message_slice()).await?,
		config::HttpMethod::POST => post(&mut h3, hostname, path, message.message_slice()).await?,
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
		message.send_response(data.freeze()).await;
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
	dns_query: &[u8],
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
	dns_query: &[u8],
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
		.send_data(bytes::Bytes::copy_from_slice(dns_query))
		.await
		.map_err(tokio::io::Error::other)?;
	Ok(pending)
}
