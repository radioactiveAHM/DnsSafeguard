use std::{net::SocketAddr, sync::Arc};

use crate::{
	CONFIG,
	chttp::genrequrlh1,
	utils::{Buffering, c_len, catch_in_buff},
};
use tokio::{io::AsyncWriteExt, time::sleep};

pub async fn http1() {
	// TLS Client
	let ctls = crate::tls::tlsconf(vec![b"http/1.1".to_vec()], CONFIG.disable_certificate_validation);
	let mut tank: Option<(Vec<u8>, SocketAddr)> = None;

	let udp = crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap();
	loop {
		log::info!("HTTP/1.1 connecting");
		let tls = crate::tls::dynamic_tls_conn_gen(&["http/1.1"], ctls.clone()).await;
		if tls.is_err() {
			log::warn!("{}", tls.unwrap_err());
			sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
			continue;
		}
		log::info!("HTTP/1.1 connection established");

		let mut tls = tls.unwrap();

		let mut dns_query = [0u8; 512];
		let mut base64_url_temp = [0u8; 1024 * 2];
		let mut url = [0; 1024 * 2];

		let mut http_resp = vec![0; 1024 * 8];
		let mut bf_http_resp: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut http_resp);

		if tank.is_some() {
			let (dns_query, addr) = tank.unwrap();
			tank = None;
			if handler(
				&mut tls,
				&udp,
				&dns_query,
				&mut base64_url_temp,
				&mut url,
				&mut bf_http_resp,
				&addr,
			)
			.await
			.is_err()
			{
				continue;
			}
		}

		loop {
			if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
				// rule check
				if (CONFIG.rules.is_some()
					&& crate::rule::rulecheck_sync(&CONFIG.rules, &mut dns_query[..query_size], addr, &udp).await)
					|| query_size < 12
				{
					continue;
				}

				if let Err(e) = handler(
					&mut tls,
					&udp,
					&dns_query[..query_size],
					&mut base64_url_temp,
					&mut url,
					&mut bf_http_resp,
					&addr,
				)
				.await
				{
					log::warn!("{e}");
					tank = Some((dns_query[..query_size].to_vec(), addr));
					break;
				}
			}
		}
	}
}

#[inline(always)]
async fn handler<IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
	c: &mut IO,
	udp: &tokio::net::UdpSocket,
	dns_query: &[u8],
	base64_url_temp: &mut [u8],
	url: &mut [u8],
	bf_http_resp: &mut tokio::io::ReadBuf<'_>,
	addr: &SocketAddr,
) -> tokio::io::Result<()> {
	let query_bs4url = base64_url::encode_to_slice(&dns_query, base64_url_temp)
		.map_err(|_| tokio::io::Error::other("base64 url encode error"))?;
	let mut b = Buffering(url, 0);
	let http_req = genrequrlh1(
		&mut b,
		CONFIG.server_name.as_bytes(),
		query_bs4url,
		&CONFIG.custom_http_path,
	);

	c.write_all(http_req).await?;

	// Handle Reciving Data
	bf_http_resp.clear();
	crate::ioutils::read_buffered_timeout(bf_http_resp, c, std::time::Duration::from_secs(CONFIG.response_timeout))
		.await?;
	let mut http_resp_size = bf_http_resp.filled().len();
	let mut http_resp = bf_http_resp.filled_mut();
	if let Some((heads_end, body_start)) = catch_in_buff(b"\r\n\r\n", http_resp) {
		let content_length = c_len(&http_resp[..heads_end]);
		if content_length == 0 {
			return Err(tokio::io::Error::other("no content-length header"));
		}

		loop {
			let body = &http_resp[body_start..http_resp_size];
			if content_length == body.len() {
				break;
			} else {
				crate::ioutils::read_buffered_timeout(
					bf_http_resp,
					c,
					std::time::Duration::from_secs(CONFIG.response_timeout),
				)
				.await?;
			}
			http_resp_size = bf_http_resp.filled().len();
			http_resp = bf_http_resp.filled_mut();
		}

		if CONFIG.overwrite.is_some() {
			crate::ipoverwrite::overwrite_ip(&mut http_resp[body_start..http_resp_size], &CONFIG.overwrite);
		}
		let _ = udp.send_to(&http_resp[body_start..http_resp_size], addr).await;
	} else {
		return Err(tokio::io::Error::other("mailformed http response"));
	}

	Ok(())
}

type RcLocker = Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>>>;

pub async fn h1_multi() {
	let ctls = crate::tls::tlsconf(vec![b"http/1.1".to_vec()], CONFIG.disable_certificate_validation);

	let udp = Arc::new(crate::udp::udp_socket(CONFIG.serve_addrs).await.unwrap());

	let (sender, recver) = tokio::sync::mpsc::channel(CONFIG.connection.h1_multi_connections);
	let recver_locker: RcLocker = Arc::new(tokio::sync::Mutex::new(recver));

	for conn_i in 0..CONFIG.connection.h1_multi_connections {
		let recver_locker = recver_locker.clone();
		let tls_config = ctls.clone();
		let udp = udp.clone();
		tokio::spawn(async move {
			loop {
				let tls_conn = crate::tls::dynamic_tls_conn_gen(&["http/1.1"], tls_config.clone()).await;
				if tls_conn.is_err() {
					log::warn!("{}", tls_conn.unwrap_err());
					tokio::time::sleep(std::time::Duration::from_secs(CONFIG.connection.reconnect_sleep)).await;
					continue;
				}
				log::info!("HTTP/1.1 connection {conn_i} established");
				let mut c = tls_conn.unwrap();

				let mut base64_url_temp = [0u8; 4096];
				let mut url = [0; 4096];
				let mut http_resp = vec![0; 1024 * 8];
				let mut bf_http_resp: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut http_resp);
				loop {
					let udp = udp.clone();
					if let Some((query, addr)) = recver_locker.lock().await.recv().await
						&& let Err(e) = handler(
							&mut c,
							&udp,
							&query,
							&mut base64_url_temp,
							&mut url,
							&mut bf_http_resp,
							&addr,
						)
						.await
					{
						log::warn!("connection {conn_i}: {e}");
						break;
					}
				}
			}
		});
	}

	let mut dns_query = [0u8; 512];
	loop {
		if let Ok((query_size, addr)) = udp.recv_from(&mut dns_query).await {
			// rule check
			if (CONFIG.rules.is_some()
				&& crate::rule::rulecheck(&CONFIG.rules, &mut dns_query[..query_size], addr, udp.clone()).await)
				|| query_size < 12
			{
				continue;
			}
			let _ = sender.send((dns_query[..query_size].to_vec(), addr)).await;
		}
	}
}
