use bytes::Bytes;
use h2::server::SendResponse;
use h2::{Reason, SendStream};
use http::Response;
use std::net::SocketAddr;

use crate::utils::recv_timeout;

use super::DnsQuery;

pub async fn serve_h2(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    udp_socket_addrs: SocketAddr,
    log: bool,
    cache_control: &'static String,
) -> tokio::io::Result<()> {
    let peer = stream.get_ref().0.peer_addr()?;
    let mut conn = match h2::server::handshake(stream).await {
        Ok(c) => c,
        Err(e) => return Err(tokio::io::Error::other(e)),
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
                        if let Err(e) =
                            handle_dns_req_post(&mut resp, body, udp_socket_addrs, cache_control)
                                .await
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
                                handle_dns_req_get(&mut resp, dq, udp_socket_addrs, cache_control)
                                    .await
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

#[inline(never)]
async fn handle_dns_req_post(
    resp: &mut SendResponse<Bytes>,
    body: Bytes,
    udp_socket_addrs: SocketAddr,
    cache_control: &'static String,
) -> tokio::io::Result<()> {
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
        match resp.send_response(
            Response::builder()
                .version(http::Version::HTTP_2)
                .status(http::status::StatusCode::SERVICE_UNAVAILABLE)
                .body(())
                .unwrap(),
            true,
        ) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(tokio::io::Error::other(e)),
        };
    }

    if let Err(e) = handle_resp(resp, &buff, size, cache_control).await {
        return Err(tokio::io::Error::other(e));
    }

    Ok(())
}

#[inline(never)]
async fn handle_dns_req_get(
    resp: &mut SendResponse<Bytes>,
    dq: DnsQuery,
    udp_socket_addrs: SocketAddr,
    cache_control: &'static String,
) -> tokio::io::Result<()> {
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
        match resp.send_response(
            Response::builder()
                .version(http::Version::HTTP_2)
                .status(http::status::StatusCode::SERVICE_UNAVAILABLE)
                .body(())
                .unwrap(),
            true,
        ) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(tokio::io::Error::other(e)),
        };
    }

    handle_resp(resp, &buff, size, cache_control).await
}

struct SendResponseHeader<'a>(&'a mut SendResponse<Bytes>, http::Response<()>);
impl Future for SendResponseHeader<'_> {
    type Output = tokio::io::Result<Result<h2::SendStream<Bytes>, h2::Error>>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let r = self.1.clone();
        match self.0.poll_reset(cx) {
            std::task::Poll::Ready(Ok(r)) => std::task::Poll::Ready(Err(tokio::io::Error::new(
                tokio::io::ErrorKind::ConnectionAborted,
                r.description(),
            ))),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(tokio::io::Error::other(e)))
            }
            std::task::Poll::Pending => std::task::Poll::Ready(Ok(self.0.send_response(r, false))),
        }
    }
}

#[inline(always)]
pub async fn h2_send_bytes(stream: &mut SendStream<Bytes>, bytes: &[u8]) -> tokio::io::Result<()> {
    let size = bytes.len();
    stream.reserve_capacity(size);
    let mut written = 0;
    loop {
        if let Some(Ok(capacity)) = std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            if capacity >= size {
                if let Err(e) = stream.send_data(Bytes::copy_from_slice(bytes), true) {
                    return Err(tokio::io::Error::other(e));
                }
                return Ok(());
            } else {
                if written + capacity >= size {
                    if let Err(e) = stream.send_data(
                        Bytes::copy_from_slice(&bytes[written..written + capacity]),
                        true,
                    ) {
                        return Err(tokio::io::Error::other(e));
                    }
                    return Ok(());
                } else if let Err(e) =
                    stream.send_data(Bytes::copy_from_slice(&bytes[written..size]), false)
                {
                    return Err(tokio::io::Error::other(e));
                }

                written += capacity;
                stream.reserve_capacity(size - written);
            }
        } else {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::ConnectionAborted,
                "Stream Closed",
            ));
        }
    }
}

#[inline(always)]
async fn handle_resp(
    rframe: &mut SendResponse<Bytes>,
    buff: &[u8],
    size: usize,
    cache_control: &'static String,
) -> tokio::io::Result<()> {
    let heads = Response::builder()
        .version(http::Version::HTTP_2)
        .status(http::status::StatusCode::OK)
        .header("Content-Type", "application/dns-message")
        .header("Cache-Control", cache_control)
        .header("Access-Control-Allow-Origin", "*")
        .header("content-length", size)
        .body(())
        .unwrap();

    if let Ok(Ok(mut bframe)) = SendResponseHeader(rframe, heads).await {
        h2_send_bytes(&mut bframe, &buff[..size]).await
    } else {
        Ok(())
    }
}
