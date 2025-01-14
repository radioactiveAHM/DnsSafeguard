use bytes::Bytes;
use h2::server::SendResponse;
use h2::Reason;
use http::Response;
use std::net::SocketAddr;

use crate::utils::recv_timeout;

use super::DnsQuery;

pub async fn serve_h2(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    udp_socket_addrs: SocketAddr,
    log: bool,
) -> std::io::Result<()> {
    let peer = stream.get_ref().0.peer_addr()?;
    let mut conn = {
        match h2::server::handshake(stream).await {
            Ok(c) => c,
            Err(e) => return Err(std::io::Error::other(e)),
        }
    };
    let mut deadloop: u8 = 0;
    loop {
        if deadloop == 20 {
            // dead tcp connection
            break;
        }
        if let Some(Ok((mut req, mut resp))) = conn.accept().await {
            deadloop = 0;
            if req.method() == http::Method::POST {
                tokio::spawn(async move {
                    if let Some(Ok(body)) = req.body_mut().data().await {
                        if let Err(e) = handle_dns_req_post(&mut resp, body, udp_socket_addrs).await
                        {
                            if log {
                                println!(
                                    "DoH2 server<{}:stream(POST):{}>: {}",
                                    peer,
                                    resp.stream_id().as_u32(),
                                    e
                                );
                            }
                        }
                    } else {
                        resp.send_reset(Reason::PROTOCOL_ERROR);
                    }
                });
            } else if req.method() == http::Method::GET {
                if let Some(bs4dns) = req.uri().query() {
                    if let Ok(dq) = DnsQuery::new(&bs4dns.as_bytes()[4..]) {
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_dns_req_get(&mut resp, dq, udp_socket_addrs).await
                            {
                                if log {
                                    println!(
                                        "DoH2 server<{}:stream(GET):{}>: {}",
                                        peer,
                                        resp.stream_id().as_u32(),
                                        e
                                    );
                                }
                            }
                        });
                    }
                } else {
                    resp.send_reset(Reason::PROTOCOL_ERROR);
                }
            } else {
                resp.send_reset(Reason::PROTOCOL_ERROR);
            }
        } else {
            deadloop += 1;
        }
    }

    Ok(())
}

async fn handle_dns_req_post(
    resp: &mut SendResponse<Bytes>,
    body: Bytes,
    udp_socket_addrs: SocketAddr,
) -> std::io::Result<()> {
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;
    agent.send(&body).await?;

    let mut buff = [0; 4096];
    let size: usize;
    if let Ok(v) = recv_timeout(&agent, &mut buff, 5).await {
        size = v;
    } else if let Ok(v) = recv_timeout(&agent, &mut buff, 10).await {
        size = v;
    } else {
        match resp.send_response(Response::builder().status(503).version(http::Version::HTTP_2).body(()).unwrap(), true) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(std::io::Error::other(e))
        };
    }

    if let Err(e) = handle_resp(resp, &buff, size).await {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ));
    }

    Ok(())
}

async fn handle_dns_req_get(
    resp: &mut SendResponse<Bytes>,
    dq: DnsQuery,
    udp_socket_addrs: SocketAddr,
) -> std::io::Result<()> {
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;
    agent.send(dq.value()).await?;

    let mut buff = [0; 4096];
    let size: usize;
    if let Ok(v) = recv_timeout(&agent, &mut buff, 5).await {
        size = v;
    } else if let Ok(v) = recv_timeout(&agent, &mut buff, 10).await {
        size = v;
    } else {
        match resp.send_response(Response::builder().status(503).version(http::Version::HTTP_2).body(()).unwrap(), true) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(std::io::Error::other(e))
        };
    }

    handle_resp(resp, &buff, size).await
}

async fn handle_resp(
    resp: &mut SendResponse<Bytes>,
    buff: &[u8],
    size: usize,
) -> std::io::Result<()> {
    if let Ok(heads) = Response::builder()
        .status(200)
        .version(http::Version::HTTP_2)
        .header("Content-Type", "application/dns-message")
        .header("Cache-Control", "max-age=300")
        .header("Content-Length", size)
        .body(())
    {
        let dq_resp = Bytes::copy_from_slice(&buff[..size]);
        let pending = resp.send_response(heads, false);

        match pending {
            Ok(mut p) => {
                p.reserve_capacity(size);
                if let Err(e) = p.send_data(dq_resp, true) {
                    return Err(std::io::Error::other(e));
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(e));
            }
        }
    }

    Ok(())
}
