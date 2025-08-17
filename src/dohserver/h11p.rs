use std::{fmt::Display, net::SocketAddr};
use tokio::{io::AsyncWriteExt, net::UdpSocket};

use crate::{
    CONFIG,
    utils::{Buffering, c_len, catch_in_buff, recv_timeout},
};

pub async fn serve_http11(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    serve_addrs: SocketAddr,
    log: bool,
    response_timeout: (u64, u64),
) -> tokio::io::Result<()> {
    let peer = stream.get_ref().0.peer_addr()?;
    let serving_ip = if serve_addrs.ip() == std::net::Ipv4Addr::UNSPECIFIED {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else if serve_addrs.ip() == std::net::Ipv6Addr::UNSPECIFIED {
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        serve_addrs.ip()
    };
    let agent = crate::udp::udp_socket(std::net::SocketAddr::new(serving_ip, 0)).await?;
    agent
        .connect(std::net::SocketAddr::new(serving_ip, serve_addrs.port()))
        .await?;

    let mut reqbuff = [0; 1024];
    let mut reqbuff: tokio::io::ReadBuf<'_> = tokio::io::ReadBuf::new(&mut reqbuff);
    let mut respbuff = [0; 4096];
    loop {
        crate::ioutils::read_buffered(&mut reqbuff, &mut stream).await?;
        if let Err(e) = handle_req(
            &mut stream,
            &mut reqbuff,
            &agent,
            &mut respbuff,
            response_timeout,
        )
        .await
            && log
        {
            log::error!("DoH1.1 server<{peer}:stream>: {e}");
        }
        reqbuff.clear();
    }
}

async fn handle_req(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    reqbuff: &mut tokio::io::ReadBuf<'_>,
    agent: &UdpSocket,
    respbuff: &mut [u8],
    response_timeout: (u64, u64),
) -> tokio::io::Result<()> {
    let req = HTTP11::parse(reqbuff, stream).await?;
    let dqbuff = match &req.method {
        Method::Get(dq) => dq.as_slice(),
        Method::Post(body_pos) => &reqbuff.filled()[*body_pos..],
    };

    agent.send(dqbuff).await?;

    let size: usize;
    if let Ok(v) = recv_timeout(agent, respbuff, response_timeout.0).await {
        size = v;
    } else if let Ok(v) = recv_timeout(agent, respbuff, response_timeout.1).await {
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
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nCache-Control: {}\r\nAccess-Control-Allow-Origin: *\r\ncontent-length: {size}\r\n\r\n",
            &CONFIG.doh_server.cache_control
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

enum Method {
    Get(Vec<u8>),
    Post(usize),
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
        reqbuff: &mut tokio::io::ReadBuf<'_>,
        mut stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> tokio::io::Result<Self> {
        if &reqbuff.filled()[..3] == b"GET" {
            if let Some(bs4dns) = HTTP11::find_query(reqbuff.filled()) {
                match base64_url::decode(bs4dns) {
                    Ok(q) => Ok(Self {
                        method: Method::Get(q),
                    }),
                    Err(e) => Err(tokio::io::Error::other(e)),
                }
            } else {
                Err(tokio::io::Error::other(HTTP11Errors::NoDnsQuery))
            }
        } else if &reqbuff.filled()[..4] == b"POST" {
            if let Some(body_pos) = catch_in_buff(b"\r\n\r\n", reqbuff.filled()) {
                let content_length = c_len(&reqbuff.filled()[..body_pos.0]);
                if content_length > 0 {
                    loop {
                        if reqbuff.filled()[body_pos.1..].len() >= content_length {
                            break;
                        }
                        crate::ioutils::read_buffered_timeout(
                            reqbuff,
                            &mut stream,
                            std::time::Duration::from_secs(5),
                        )
                        .await?;
                    }
                    Ok(Self {
                        method: Method::Post(body_pos.1),
                    })
                } else {
                    Err(tokio::io::Error::other(HTTP11Errors::MalformedHttp))
                }
            } else {
                Err(tokio::io::Error::other(HTTP11Errors::MalformedHttp))
            }
        } else {
            Err(tokio::io::Error::other(HTTP11Errors::InvalidMethod))
        }
    }
}
