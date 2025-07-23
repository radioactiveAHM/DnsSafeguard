use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::{net::TcpStream, time::sleep};

pub fn get_interface(ipv4: bool, interface: &str) -> SocketAddr {
    // Cause panic if it fails, informing the user that the binding interface is not available.
    let interfaces =
        local_ip_address::list_afinet_netifas().expect("binding interface is not available");

    let ip = interfaces.iter().find(|i| {
        if ipv4 {
            i.0.as_str().to_lowercase() == interface.to_lowercase() && i.1.is_ipv4()
        } else {
            i.0.as_str().to_lowercase() == interface.to_lowercase() && i.1.is_ipv6()
        }
    });

    if ip.is_none() {
        println!(
            "interface not found or interface does not provide IPv6.\nAvailable interface are:"
        );
        for interface in interfaces {
            println!("{}: {}", interface.0, interface.1);
        }
        std::process::exit(1);
    }

    match ip.unwrap().1 {
        IpAddr::V4(ip) => {
            println!("{ip} Selected for binding");
            std::net::SocketAddr::V4(SocketAddrV4::new(ip, 0))
        }
        IpAddr::V6(ip) => {
            println!("[{ip}] Selected for binding");
            std::net::SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0))
        }
    }
}

pub fn set_tcp_socket_options(tcp: &mut tokio::net::TcpSocket) {
    let options = crate::get_socket_op();
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
    target: std::net::SocketAddr,
    connection_cfg: crate::config::Connection,
    network_interface: &'static Option<String>,
) -> TcpStream {
    let mut retry = 0u8;
    loop {
        let mut socket = if target.is_ipv4() {
            tokio::net::TcpSocket::new_v4().expect("Could not create socket v4")
        } else {
            tokio::net::TcpSocket::new_v6().expect("Could not create socket v6")
        };

        set_tcp_socket_options(&mut socket);

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
                println!("{e}");
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
