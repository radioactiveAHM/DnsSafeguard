use bytes::Bytes;
use h2::server::SendResponse;
use h2::Reason;
use http::Response;
use std::net::SocketAddr;
use tokio::time::timeout;

use super::DnsQuery;

pub async fn serve_h2(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    udp_socket_addrs: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.get_ref().0.peer_addr()?;
    let mut conn = h2::server::handshake(stream).await?;
    let mut deadloop: u8 = 0;
    loop {
        if deadloop == 20 {
            // dead tcp connection
            break;
        }
        if let Some(Ok((mut req, mut resp))) = conn.accept().await {
            deadloop = 0;
            if let Some(bs4dns) = req.uri().query() {
                if let Ok(dq) = DnsQuery::new(&bs4dns.as_bytes()[4..]) {
                    tokio::spawn(async move {
                        if let Err(e) = handle_dns_req_get(&mut resp, dq, udp_socket_addrs).await {
                            resp.send_reset(Reason::INTERNAL_ERROR);
                            println!(
                                "DoH2 server<{}:stream(GET):{}>: {}",
                                peer,
                                resp.stream_id().as_u32(),
                                e
                            );
                        }
                    });
                }
            } else if req.method() == http::Method::POST {
                let body: Option<Result<Bytes, h2::Error>> = req.body_mut().data().await;
                if body.is_none() {
                    continue;
                }
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_dns_req_post(&mut resp, body.unwrap(), udp_socket_addrs).await
                    {
                        resp.send_reset(Reason::INTERNAL_ERROR);
                        println!(
                            "DoH2 server<{}:stream(POST):{}>: {}",
                            peer,
                            resp.stream_id().as_u32(),
                            e
                        );
                    }
                });
            }
        } else {
            deadloop += 1;
        }
    }

    Ok(())
}

async fn handle_dns_req_post(
    resp: &mut SendResponse<Bytes>,
    body: Result<Bytes, h2::Error>,
    udp_socket_addrs: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let dns = body?;
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;
    agent.send(&dns).await?;

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
        let rto = timeout(std::time::Duration::from_secs(5), async {
            handle_resp(resp, &buff, size).await
        })
        .await;

        if let Ok(inside) = rto {
            inside?;
        } else {
            resp.send_reset(Reason::SETTINGS_TIMEOUT);
        }
    } else {
        resp.send_reset(Reason::INTERNAL_ERROR);
    }

    Ok(())
}

async fn handle_dns_req_get(
    resp: &mut SendResponse<Bytes>,
    dq: DnsQuery,
    udp_socket_addrs: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let agent = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    agent.connect(udp_socket_addrs).await?;
    agent.send(dq.value()).await?;

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
        let rto = timeout(std::time::Duration::from_secs(5), async {
            handle_resp(resp, &buff, size).await
        })
        .await;

        if let Ok(inside) = rto {
            inside?;
        } else {
            resp.send_reset(Reason::SETTINGS_TIMEOUT);
        }
    } else {
        resp.send_reset(Reason::INTERNAL_ERROR);
    }

    Ok(())
}

async fn handle_resp(
    resp: &mut SendResponse<Bytes>,
    buff: &[u8],
    size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let dq_resp = Bytes::copy_from_slice(&buff[..size]);
    let pending = resp.send_response(
        Response::builder()
            .status(200)
            .header("Content-Type", "application/dns-message")
            .header("Cache-Control", "max-age=300")
            .header("Content-Length", size)
            .body(())?,
        false,
    );

    if let Ok(mut p) = pending {
        p.reserve_capacity(size);
        let _ = p.send_data(dq_resp, true);
    }

    Ok(())
}
