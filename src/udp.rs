pub async fn udp_socket(
    serve_addrs: std::net::SocketAddr,
) -> tokio::io::Result<tokio::net::UdpSocket> {
    let ipversion = if serve_addrs.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(
        ipversion,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // Allow dual stack
    if serve_addrs.is_ipv6()
        && let Err(e) = socket.set_only_v6(false)
    {
        log::warn!("UDP socket set_only_v6 option: {e}")
    }

    // Set Nonblocking
    if let Err(e) = socket.set_nonblocking(true) {
        log::warn!("UDP Set Nonblocking: {e}")
    }

    socket.bind(&serve_addrs.into())?;

    tokio::net::UdpSocket::from_std(socket.into())
}

pub fn udp_addr_to_bind(
    network_interface: &'static Option<String>,
    v4: bool,
) -> std::net::SocketAddr {
    if let Some(interface) = network_interface {
        crate::interface::get_interface(v4, interface.as_str())
    } else {
        let default = if v4 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };

        std::net::SocketAddr::new(default, 0)
    }
}
