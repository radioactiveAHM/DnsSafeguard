use std::{fmt::Display, net::SocketAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, time::timeout};

use crate::{c_len, catch_in_buff};

use super::DnsQuery;

pub async fn serve_http11(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    udp_socket_addrs: SocketAddr,
    log: bool
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.get_ref().0.peer_addr()?;
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;

    let mut deadloop = 0u8;
    loop {
        if deadloop==20 {break;}

        let mut buff = [0;8196];
        if let Ok(size) = stream.read(&mut buff).await {
            if size > 5 {
                deadloop=0;
                if let Err(e) = handle_req(&mut stream, &buff[..size], &agent).await {
                    if log {
                        println!("DoH1.1 server<{}:stream>: {}", peer, e);
                    }
                }
            } else {
                deadloop+=1;
            }
        }else {
            deadloop+=1;
        }
        
    }
    Ok(())
}

async fn handle_req(stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>, buff: &[u8], agent: &UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    let req = HTTP11::parse(buff, stream).await?;
    let dqbuff = req.getbuff();

    agent.send(dqbuff).await?;

    let mut buff = [0; 8196];
    let size: usize;
    if let Ok(v) = timeout(std::time::Duration::from_secs(5), async {
        agent.recv(&mut buff).await
    })
    .await
    {
        size = v?;
    } else {
        size = agent.recv(&mut buff).await?;
    }

    if size > 5 {
        stream.write(
            format!(
                "HTTP/1.1 OK 200\r\nContent-Type: application/dns-message\r\nCache-Contro: max-age=300\r\nContent-Length: {}\r\n\r\n",
                size
            ).as_bytes()
        ).await?;
        stream.write(&buff[..size]).await?;
    } else {
        stream.write(b"HTTP/1.1 OK 404\r\n\r\n").await?;
    }

    Ok(())
}

#[derive(Debug)]
enum HTTP11Errors {
    NoDnsQuery,
    InvalidMethod,
    MalformedHttp
}
impl Display for HTTP11Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HTTP11Errors::NoDnsQuery => write!(f, "NoDnsQuery"),
            HTTP11Errors::InvalidMethod => write!(f, "InvalidMethod"),
            HTTP11Errors::MalformedHttp => write!(f, "MalformedHttp")
        }
    }
}
impl std::error::Error for HTTP11Errors {}
enum Method{
    GET(DnsQuery),
    POST([u8;512], usize)
}
struct HTTP11 {
    method: Method
}
impl HTTP11 {
    fn find_query(buff: &[u8]) -> Option<&[u8]> {
        let a = catch_in_buff(b"?dns=", buff)?;
        let b = catch_in_buff(b" HTTP/1.1", buff)?;
        Some(&buff[a.1..b.0])
    }
    async fn parse(buff: &[u8], stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Result<Self, Box<dyn std::error::Error>> {
        if &buff[..3]==b"GET" {
            if let Some(query) = HTTP11::find_query(buff) {
                Ok(Self {
                    method: Method::GET(DnsQuery::new(query)?)
                })
            }else {
                Err(Box::new(HTTP11Errors::NoDnsQuery))
            }
        } else if &buff[..4]==b"POST" {
            if let Some(body_pos) = catch_in_buff(b"\r\n\r\n", buff) {
                let content_length = c_len(&buff[..body_pos.0]);
                if content_length==0{
                    Err(Box::new(HTTP11Errors::MalformedHttp))
                }else {
                    let mut dns = [0u8;512];
                    dns[..buff[body_pos.1..].len()].copy_from_slice(&buff[body_pos.1..]);
                    if content_length!=buff[body_pos.1..].len() {
                        let mut b2 = [0; 512];
                        let size = stream.read(&mut b2).await?;
                        dns[buff[body_pos.1..].len()..buff[body_pos.1..].len()+size].copy_from_slice(&b2[..size]);
                        Ok(Self { method: Method::POST(dns, buff[body_pos.1..].len()+size) })
                    }else {
                        Ok(Self { method: Method::POST(dns, buff[body_pos.1..].len()) })
                    }
                }
            } else {
                Err(Box::new(HTTP11Errors::MalformedHttp))
            }
        } else {
            Err(Box::new(HTTP11Errors::InvalidMethod))
        }
    }

    fn getbuff(&self)-> &[u8] {
        match &self.method {
            Method::GET(dq)=>{
                dq.value()
            },
            Method::POST(buff, size) => {
                &buff[..*size]
            }
        }
    }
}