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
    if serve_addrs.is_ipv6() {
        if let Err(e) = socket.set_only_v6(false) {
            println!("UDP socket set_only_v6 option: {e}")
        }
    }

    socket.bind(&serve_addrs.into())?;

    tokio::net::UdpSocket::from_std(socket.into())
}
