use std::{fmt::Display, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

use crate::utils::{c_len, catch_in_buff, recv_timeout, Buffering};

use super::DnsQuery;

pub async fn serve_http11(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    udp_socket_addrs: SocketAddr,
    log: bool,
    cache_control: &'static String
) -> tokio::io::Result<()> {
    let peer = stream.get_ref().0.peer_addr()?;
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;

    let mut deadloop = 0u8;
    let mut buff = [0; 1024];
    let mut respbuff = [0; 4096];
    loop {
        if deadloop == 20 {
            break;
        }
        if let Ok(size) = stream.read(&mut buff).await {
            if size > 39 {
                deadloop = 0;
                if let Err(e) = handle_req(
                    &mut stream,
                    &buff[..size],
                    &agent,
                    &mut respbuff,
                    log,
                    &peer,
                    cache_control
                )
                .await
                {
                    if log {
                        println!("DoH1.1 server<{}:stream>: {}", peer, e);
                    }
                }
            } else {
                deadloop += 1;
            }
        } else {
            deadloop += 1;
        }
    }
    Ok(())
}

async fn handle_req(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    buff: &[u8],
    agent: &UdpSocket,
    respbuff: &mut [u8],
    log: bool,
    peer: &SocketAddr,
    cache_control: &'static String
) -> tokio::io::Result<()> {
    let req = {
        match HTTP11::parse(buff, stream).await {
            Ok(h) => h,
            Err(e) => {
                if log {
                    println!("DoH1.1 server<{}:stream>: {}", peer, e);
                }
                return Ok(());
            }
        }
    };
    let dqbuff = req.getbuff();

    agent.send(dqbuff).await?;

    let size: usize;
    if let Ok(v) = recv_timeout(agent, respbuff, 5).await {
        size = v;
    } else if let Ok(v) = recv_timeout(agent, respbuff, 10).await {
        size = v;
    } else {
        let _ = stream
            .write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            .await?;
        return Err(tokio::io::Error::from(tokio::io::ErrorKind::TimedOut));
    }

    let mut temp = [0u8; 4096];
    let _ = stream.write(
        Buffering(&mut temp, 0)
    .write(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nCache-Control: {cache_control}\r\nAccess-Control-Allow-Origin: *\r\nServer: HTTP server\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\ncontent-length: {size}\r\n\r\n"
        ).as_bytes()
    ).write(&respbuff[..size]).get()
    ).await?;

    Ok(())
}

#[derive(Debug)]
enum HTTP11Errors {
    NoDnsQuery,
    InvalidMethod,
    MalformedHttp,
}
impl Display for HTTP11Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HTTP11Errors::NoDnsQuery => write!(f, "NoDnsQuery"),
            HTTP11Errors::InvalidMethod => write!(f, "InvalidMethod"),
            HTTP11Errors::MalformedHttp => write!(f, "MalformedHttp"),
        }
    }
}
impl std::error::Error for HTTP11Errors {}

#[allow(clippy::large_enum_variant)]
enum Method {
    Get(DnsQuery),
    Post([u8; 512], usize),
}
struct HTTP11 {
    method: Method,
}
impl HTTP11 {
    fn find_query(buff: &[u8]) -> Option<&[u8]> {
        let a = catch_in_buff(b"?dns=", buff)?;
        let b = catch_in_buff(b" HTTP/1.1", buff)?;
        Some(&buff[a.1..b.0])
    }
    async fn parse(
        buff: &[u8],
        stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> tokio::io::Result<Self> {
        if &buff[..3] == b"GET" {
            if let Some(query) = HTTP11::find_query(buff) {
                Ok(Self {
                    method: Method::Get(DnsQuery::new(query)?),
                })
            } else {
                Err(tokio::io::Error::other(HTTP11Errors::NoDnsQuery))
            }
        } else if &buff[..4] == b"POST" {
            if let Some(body_pos) = catch_in_buff(b"\r\n\r\n", buff) {
                let content_length = c_len(&buff[..body_pos.0]);
                if content_length == 0 {
                    Err(tokio::io::Error::other(HTTP11Errors::MalformedHttp))
                } else {
                    let mut dns = [0u8; 512];
                    dns[..buff[body_pos.1..].len()].copy_from_slice(&buff[body_pos.1..]);
                    if content_length != buff[body_pos.1..].len() {
                        let mut b2 = [0; 512];
                        let size = stream.read(&mut b2).await?;
                        dns[buff[body_pos.1..].len()..buff[body_pos.1..].len() + size]
                            .copy_from_slice(&b2[..size]);
                        Ok(Self {
                            method: Method::Post(dns, buff[body_pos.1..].len() + size),
                        })
                    } else {
                        Ok(Self {
                            method: Method::Post(dns, buff[body_pos.1..].len()),
                        })
                    }
                }
            } else {
                Err(tokio::io::Error::other(HTTP11Errors::MalformedHttp))
            }
        } else {
            Err(tokio::io::Error::other(HTTP11Errors::InvalidMethod))
        }
    }

    fn getbuff(&self) -> &[u8] {
        match &self.method {
            Method::Get(dq) => dq.value(),
            Method::Post(buff, size) => &buff[..*size],
        }
    }
}
