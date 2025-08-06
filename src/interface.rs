use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

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

    #[cfg(target_os = "linux")]
    {
        if let Some(device) = &options.linux.bind_to_device {
            if tcp_options::set_tcp_bind_device(tcp, device).is_err() {
                println!("Failed to set bind_to_device socket option");
            }
        }
        if let Some(congestion) = &options.linux.congestion {
            if tcp_options::set_tcp_congestion(tcp, congestion).is_err() {
                println!("Failed to set congestion socket option");
            }
        }
        if let Some(mss) = options.linux.mss {
            if tcp_options::set_tcp_mss(tcp, mss).is_err() {
                println!("Failed to set mss socket option");
            }
        }
    }
}

pub async fn tcp_connect_handle(
    target: std::net::SocketAddr,
    connection_cfg: crate::config::Connection,
    network_interface: &'static Option<String>,
) -> TcpStream {
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
            let default = if target.is_ipv4() {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            };

            socket
                .bind(std::net::SocketAddr::new(default, 0))
                .expect("Could not bind socket")
        };

        match socket.connect(target).await {
            Ok(stream) => {
                return stream;
            }
            Err(e) => {
                println!("TCP Connection: {e}");
                sleep(std::time::Duration::from_secs(
                    connection_cfg.reconnect_sleep,
                ))
                .await;
                continue;
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod tcp_options {
    pub fn set_tcp_mss(socket: &tokio::net::TcpSocket, mss: i32) -> Result<(), ()> {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(socket);

        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mss as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if result == -1 {
            return Err(());
        }
        Ok(())
    }
    pub fn set_tcp_congestion(socket: &tokio::net::TcpSocket, congestion: &str) -> Result<(), ()> {
        if let Ok(c) = std::ffi::CString::new(congestion) {
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(socket);

            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    c.as_ptr() as *const _,
                    c.to_bytes().len() as libc::socklen_t,
                )
            };
            if result == -1 {
                return Err(());
            }
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn set_tcp_bind_device(socket: &tokio::net::TcpSocket, device: &str) -> Result<(), ()> {
        if let Ok(device) = std::ffi::CString::new(device) {
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(socket);

            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    device.as_ptr() as *const _,
                    device.to_bytes().len() as libc::socklen_t,
                )
            };
            if result == -1 {
                return Err(());
            }
            Ok(())
        } else {
            Err(())
        }
    }
}
