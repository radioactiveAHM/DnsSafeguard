use std::{net::SocketAddr, str::FromStr, sync::Arc};

use crate::{catch_in_buff, config::Rules};

pub async fn rulecheck(
    rules: Arc<Rules>,
    dq: ([u8; 512], usize),
    client_addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> bool {
    for rule in &rules.rule {
        if rule.target=="block"{
            for option in &rule.options {
                if let Some(_) = catch_in_buff(option.as_bytes(), &dq.0[..dq.1]){
                    return true;
                }
            }
        }else {
            for option in &rule.options {
                if let Some(_) = catch_in_buff(option.as_bytes(), &dq.0[..dq.1]) {
                    let bypass_target = SocketAddr::from_str(&rule.target).unwrap();
                    tokio::spawn(async move {
                        if let Err(e) = handle_bypass(dq, client_addr, bypass_target, udp).await{
                            println!("{e}");
                        };
                    });
                    return true;
                }
            }
        }
    }

    return false;
}

async fn handle_bypass(
    dq: ([u8; 512], usize),
    client_addr: SocketAddr,
    bypass_target: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> Result<(), Box<dyn std::error::Error>> {
    // stage 1: send udp query to dns server
    let agent = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    agent.connect(bypass_target).await?;
    agent.send(&dq.0[..dq.1]).await?;

    // stage 2: recv udp query from dns server
    let mut buff = [0; 512];
    let dq_resp_size = agent.recv(&mut buff).await?;
    udp.send_to(&buff[..dq_resp_size], client_addr).await?;

    Ok(())
}
