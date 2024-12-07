use core::str;
use std::str::Utf8Error;
use tokio::{net::TcpStream, time::sleep};

#[allow(unused)]
pub fn convert_u16_to_two_u8s_be(integer: u16) -> [u8; 2] {
    [(integer >> 8) as u8, integer as u8]
}
#[allow(unused)]
pub fn convert_two_u8s_to_u16_be(bytes: [u8; 2]) -> u16 {
    ((bytes[0] as u16) << 8) | bytes[1] as u16
}

pub async fn tcp_connect_handle(
    socket_addrs: std::net::SocketAddr,
    connection_cfg: crate::config::Connection,
) -> TcpStream {
    let mut retry = 0u8;
    loop {
        match tokio::net::TcpStream::connect(socket_addrs).await {
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

#[derive(Clone, Copy)]
pub struct SNI([u8; 255], usize);
impl SNI {
    pub fn new(server_name: String) -> Self {
        if server_name.len() > 255 {
            panic!("Error: The server name exceeds the maximum allowed length of 255 characters. Please provide a shorter server name.")
        }
        let mut sni = SNI([0; 255], server_name.len());
        sni.0[..server_name.len()].copy_from_slice(server_name.as_bytes());
        sni
    }
    pub fn slice(&self) -> &[u8] {
        &self.0[..self.1]
    }

    pub fn string(&self) -> &str {
        str::from_utf8(&self.0[..self.1]).expect("Error: Invalid UTF-8 sequence")
    }
}

pub struct Buffering<'a>(pub &'a mut [u8], pub usize);
impl<'a> Buffering<'a> {
    pub fn write(&mut self, buff: &[u8]) -> &mut Self {
        self.0[self.1..self.1 + buff.len()].copy_from_slice(buff);
        self.1 += buff.len();
        self
    }
    pub fn get(&self) -> &[u8] {
        &self.0[..self.1]
    }
    pub fn str(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.0[..self.1])
    }
}
