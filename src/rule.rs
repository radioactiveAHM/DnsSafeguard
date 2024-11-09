use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use tokio::time::timeout;

use crate::catch_in_buff;

pub type Rules = Option<Vec<Rule>>;

pub async fn rulecheck(
    rules: Arc<Option<Vec<Rule>>>,
    dq: ([u8; 512], usize),
    client_addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> bool {
    for rule in rules.as_deref().unwrap() {
        if rule.target == "block" {
            for option in &rule.options {
                if catch_in_buff(option, &dq.0[..dq.1]).is_some() {
                    return true;
                }
            }
        } else {
            for option in &rule.options {
                if catch_in_buff(option, &dq.0[..dq.1]).is_some() {
                    let bypass_target = SocketAddr::from_str(&rule.target).unwrap();
                    tokio::spawn(async move {
                        if let Err(e) = handle_bypass(dq, client_addr, bypass_target, udp).await {
                            println!("{e}");
                        };
                    });
                    return true;
                }
            }
        }
    }

    false
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
    let dq_resp_size = timeout(Duration::from_secs(5), async {
        agent.recv(&mut buff).await.unwrap_or(0)
    })
    .await;
    if let Ok(size) = dq_resp_size {
        udp.send_to(&buff[..size], client_addr).await?;
    } else {
        return Err(Box::new(std::io::Error::from(std::io::ErrorKind::TimedOut)));
    }

    Ok(())
}

pub async fn rulecheck_sync(
    rules: &Option<Vec<Rule>>,
    dq: ([u8; 512], usize),
    client_addr: SocketAddr,
    udp: &tokio::net::UdpSocket,
) -> bool {
    for rule in rules.as_deref().unwrap() {
        if rule.target == "block" {
            for option in &rule.options {
                if catch_in_buff(option, &dq.0[..dq.1]).is_some() {
                    return true;
                }
            }
        } else {
            for option in &rule.options {
                if catch_in_buff(option, &dq.0[..dq.1]).is_some() {
                    let bypass_target = SocketAddr::from_str(&rule.target).unwrap();
                    if let Err(e) = handle_bypass_sync(dq, client_addr, bypass_target, udp).await {
                        println!("{e}");
                    };
                    return true;
                }
            }
        }
    }

    false
}

async fn handle_bypass_sync(
    dq: ([u8; 512], usize),
    client_addr: SocketAddr,
    bypass_target: SocketAddr,
    udp: &tokio::net::UdpSocket,
) -> Result<(), Box<dyn std::error::Error>> {
    // stage 1: send udp query to dns server
    let agent = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    agent.connect(bypass_target).await?;
    agent.send(&dq.0[..dq.1]).await?;

    // stage 2: recv udp query from dns server
    let mut buff = [0; 512];
    let dq_resp_size = timeout(Duration::from_secs(5), async {
        agent.recv(&mut buff).await.unwrap_or(0)
    })
    .await;
    if let Ok(size) = dq_resp_size {
        udp.send_to(&buff[..size], client_addr).await?;
    } else {
        return Err(Box::new(std::io::Error::from(std::io::ErrorKind::TimedOut)));
    }

    Ok(())
}

#[derive(Clone)]
pub struct Rule {
    pub options: Vec<Vec<u8>>,
    pub target: String,
}
pub fn convert_rules(config_rules: Option<Vec<crate::config::Rule>>) -> Option<Vec<Rule>> {
    if let Some(cr) = config_rules {
        if !cr.is_empty() {
            let r = cr
                .iter()
                .map(|config_rule| {
                    let options = config_rule
                        .options
                        .iter()
                        .map(|option| {
                            if option.contains(".") {
                                let mut temp = Vec::new();
                                for p in option.split(".") {
                                    if !p.is_empty() && p != " " {
                                        let mut ptemp = p.as_bytes().to_vec();
                                        ptemp.insert(0, p.len() as u8);
                                        temp.append(&mut ptemp);
                                    }
                                }

                                temp
                            } else {
                                option.as_bytes().to_vec()
                            }
                        })
                        .collect();

                    Rule {
                        options,
                        target: config_rule.target.clone(),
                    }
                })
                .collect();

            Some(r)
        } else {
            None
        }
    } else {
        None
    }
}
