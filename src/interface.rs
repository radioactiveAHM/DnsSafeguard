use std::net::SocketAddr;

use tokio::{net::TcpStream, time::sleep};

pub fn get_interface(ipv4: bool, interface: &str) -> SocketAddr {
	// Cause panic if it fails, informing the user that the binding interface is not available.
	let interfaces = local_ip_address::list_afinet_netifas().expect("binding interface is not available");

	let ip = interfaces.iter().find(|i| {
		if ipv4 {
			i.0.as_str().to_lowercase() == interface.to_lowercase() && i.1.is_ipv4()
		} else {
			i.0.as_str().to_lowercase() == interface.to_lowercase() && i.1.is_ipv6()
		}
	});

	if let Some(ip) = ip {
		log::info!("{} selected for binding", ip.1);
		SocketAddr::new(ip.1, 0)
	} else {
		log::warn!("interface not found or interface does not provide IPv6.\navailable interface are:");
		for interface in interfaces {
			println!("{}: {}", interface.0, interface.1);
		}
		std::process::exit(1);
	}
}

pub fn set_tcp_socket_options(tcp: &mut tokio::net::TcpSocket, options: &crate::config::TcpSocketOptions) {
	if let Some(send_buffer_size) = options.send_buffer_size {
		tcp.set_send_buffer_size(send_buffer_size).unwrap();
	}
	if let Some(recv_buffer_size) = options.recv_buffer_size {
		tcp.set_recv_buffer_size(recv_buffer_size).unwrap();
	}
	if let Some(nodelay) = options.nodelay {
		tcp.set_nodelay(nodelay).unwrap();
	}
	if let Some(keepalive) = options.keepalive {
		tcp.set_keepalive(keepalive).unwrap();
	}
}

pub async fn tcp_connect_handle(
	target: SocketAddr,
	connection_cfg: crate::config::Connection,
	network_interface: &Option<String>,
	options: &crate::config::TcpSocketOptions,
) -> TcpStream {
	loop {
		let mut socket = if target.is_ipv4() {
			tokio::net::TcpSocket::new_v4().expect("could not create socket v4")
		} else {
			tokio::net::TcpSocket::new_v6().expect("could not create socket v6")
		};

		set_tcp_socket_options(&mut socket, options);

		if let Some(interface) = network_interface {
			socket
				.bind(get_interface(target.is_ipv4(), interface.as_str()))
				.expect("could not bind socket")
		} else {
			let default = if target.is_ipv4() {
				std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
			} else {
				std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
			};

			socket.bind(SocketAddr::new(default, 0)).expect("could not bind socket")
		};

		log::info!("TCP socket connecting to {target}");
		match socket.connect(target).await {
			Ok(stream) => {
				log::info!("TCP socket connected to {target}");
				return stream;
			}
			Err(e) => {
				log::warn!("TCP connection: {e}");
				sleep(std::time::Duration::from_secs(connection_cfg.reconnect_sleep)).await;
				continue;
			}
		}
	}
}
