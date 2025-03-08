use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::{net::TcpStream, time::sleep};

pub fn get_interface(ipv4: bool, interface: &str) -> SocketAddr {
    // Cause panic if it fails, informing the user that the binding interface is not available.
    match local_ip_address::list_afinet_netifas()
        .expect("binding interface is not available")
        .iter()
        .find(|i| {
            if ipv4 {
                i.0.as_str() == interface && i.1.is_ipv4()
            } else {
                i.0.as_str() == interface && i.1.is_ipv6()
            }
        })
        .expect("interface not found or interface does not provide IPv6")
        .1
    {
        IpAddr::V4(ip) => std::net::SocketAddr::V4(SocketAddrV4::new(ip, 0)),
        IpAddr::V6(ip) => std::net::SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0)),
    }
}

pub async fn tcp_connect_handle(
    target: std::net::SocketAddr,
    connection_cfg: crate::config::Connection,
    network_interface: &'static Option<String>,
) -> TcpStream {
    let mut retry = 0u8;
    loop {
        let socket = if target.is_ipv4() {
            tokio::net::TcpSocket::new_v4().expect("Could not create socket v4")
        } else {
            tokio::net::TcpSocket::new_v6().expect("Could not create socket v6")
        };

        if let Some(interface) = network_interface {
            socket
                .bind(get_interface(target.is_ipv4(), interface.as_str()))
                .expect("Could not bind socket")
        } else {
            socket
                .bind(std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    0,
                )))
                .expect("Could not bind socket")
        };

        match socket.connect(target).await {
            Ok(stream) => {
                return stream;
            }
            Err(e) => {
                if retry == connection_cfg.max_reconnect {
                    println!(
                        "Max retry reached. Sleeping for {}",
                        connection_cfg.max_reconnect_sleep
                    );
                    sleep(std::time::Duration::from_secs(
                        connection_cfg.max_reconnect_sleep,
                    ))
                    .await;
                    retry = 0;
                    continue;
                }
                println!("{}", e);
                retry += 1;
                sleep(std::time::Duration::from_secs(
                    connection_cfg.reconnect_sleep,
                ))
                .await;
                continue;
            }
        }
    }
}
