use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use crate::{
    CONFIG,
    config::TargetType,
    utils::{Buffering, catch_in_buff},
};

pub struct Rule {
    pub options: Vec<Vec<u8>>,
    pub target: TargetType,
}

#[derive(serde::Deserialize)]
pub struct RuleRaw {
    pub options: Vec<String>,
    pub target: TargetType,
}

pub fn deserialize_rule<'de, D>(deserializer: D) -> Result<Option<Vec<Rule>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    if let Some(cr) = &<Option<Vec<RuleRaw>> as serde::Deserialize>::deserialize(deserializer)? {
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

            Ok(Some(r))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub async fn rulecheck(
    rules: &'static Option<Vec<Rule>>,
    dq: &mut [u8],
    client_addr: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> bool {
    for rule in rules.as_deref().unwrap() {
        match &rule.target {
            TargetType::block(t) => {
                for option in &rule.options {
                    if catch_in_buff(option, dq).is_some() {
                        match t {
                            Some(tv) => {
                                let dq_size = dq.len();
                                let dq_type = &dq[dq_size - 4..dq_size - 2];
                                if tv.iter().any(|target| target.octets() == dq_type) {
                                    let resp = dq;
                                    resp[2] = 133;
                                    resp[3] = 128;
                                    let _ = udp.send_to(resp, client_addr).await;
                                    return true;
                                }
                            }
                            None => {
                                let resp = dq;
                                resp[2] = 133;
                                resp[3] = 128;
                                let _ = udp.send_to(resp, client_addr).await;
                                return true;
                            }
                        }
                    }
                }
            }
            TargetType::dns(dns_server) => {
                for option in &rule.options {
                    if catch_in_buff(option, dq).is_some() {
                        let dns_server = *dns_server;
                        let dq = dq.to_vec();
                        tokio::spawn(async move {
                            if let Err(e) = handle_bypass(dq, client_addr, dns_server, udp).await {
                                log::error!("Bypass<{dns_server}>: {e}");
                            };
                        });
                        return true;
                    }
                }
            }
            TargetType::ip(ip, ip2) => {
                for option in &rule.options {
                    if catch_in_buff(option, dq).is_some() {
                        let mut temp = [0; 1024];
                        let mut resp = Buffering(&mut temp, 0);
                        match ip {
                            IpAddr::V4(ipv4) => {
                                if gen_resp_v4(dq, &mut resp, ipv4) {
                                    let _ = udp.send_to(resp.get(), client_addr).await;
                                    return true;
                                }
                            }
                            IpAddr::V6(ipv6) => {
                                if gen_resp_v6(dq, &mut resp, ipv6) {
                                    let _ = udp.send_to(resp.get(), client_addr).await;
                                    return true;
                                }
                            }
                        }
                        if let Some(ipv6) = ip2 {
                            if gen_resp_v6(dq, &mut resp, ipv6) {
                                let _ = udp.send_to(resp.get(), client_addr).await;
                                return true;
                            } else {
                                return false;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

async fn handle_bypass(
    dq: Vec<u8>,
    client_addr: SocketAddr,
    bypass_target: SocketAddr,
    udp: Arc<tokio::net::UdpSocket>,
) -> tokio::io::Result<usize> {
    let agent = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    agent.connect(bypass_target).await?;
    agent.send(&dq).await?;

    let mut buf = [0; 4096];
    let (size, _) =
        crate::keepalive::recv_timeout(&agent, Some(CONFIG.response_timeout), &mut buf).await?;
    udp.send_to(&buf[..size], client_addr).await
}

pub async fn rulecheck_sync(
    rules: &Option<Vec<Rule>>,
    dq: &mut [u8],
    client_addr: SocketAddr,
    udp: &tokio::net::UdpSocket,
) -> bool {
    for rule in rules.as_ref().unwrap() {
        match &rule.target {
            TargetType::block(t) => {
                for option in &rule.options {
                    if catch_in_buff(option, dq).is_some() {
                        match t {
                            Some(tv) => {
                                let dq_type = &dq[dq.len() - 4..dq.len() - 2];
                                if tv.iter().any(|target| target.octets() == dq_type) {
                                    dq[2] = 133;
                                    dq[3] = 128;
                                    let _ = udp.send_to(dq, client_addr).await;
                                    return true;
                                }
                            }
                            None => {
                                dq[2] = 133;
                                dq[3] = 128;
                                let _ = udp.send_to(dq, client_addr).await;
                                return true;
                            }
                        }
                    }
                }
            }
            TargetType::dns(dns_server) => {
                for option in &rule.options {
                    if catch_in_buff(option, dq).is_some() {
                        if let Err(e) = handle_bypass_sync(dq, client_addr, *dns_server, udp).await
                        {
                            log::error!("{e}");
                        };
                        return true;
                    }
                }
            }
            TargetType::ip(ip, ip2) => {
                for option in &rule.options {
                    if catch_in_buff(option, dq).is_some() {
                        let mut temp = [0; 1024];
                        let mut resp = Buffering(&mut temp, 0);
                        match ip {
                            IpAddr::V4(ipv4) => {
                                if gen_resp_v4(dq, &mut resp, ipv4) {
                                    let _ = udp.send_to(resp.get(), client_addr).await;
                                    return true;
                                }
                            }
                            IpAddr::V6(ipv6) => {
                                if gen_resp_v6(dq, &mut resp, ipv6) {
                                    let _ = udp.send_to(resp.get(), client_addr).await;
                                    return true;
                                }
                            }
                        }
                        if let Some(ipv6) = ip2 {
                            if gen_resp_v6(dq, &mut resp, ipv6) {
                                let _ = udp.send_to(resp.get(), client_addr).await;
                                return true;
                            } else {
                                return false;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

async fn handle_bypass_sync(
    dq: &[u8],
    client_addr: SocketAddr,
    bypass_target: SocketAddr,
    udp: &tokio::net::UdpSocket,
) -> tokio::io::Result<usize> {
    // stage 1: send udp query to dns server
    let agent = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    agent.connect(bypass_target).await?;
    agent.send(dq).await?;

    // stage 2: recv udp query from dns server
    let mut buf = [0; 4096];
    let (size, _) =
        crate::keepalive::recv_timeout(&agent, Some(CONFIG.response_timeout), &mut buf).await?;
    udp.send_to(&buf[..size], client_addr).await
}

#[derive(serde::Deserialize, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum Targets {
    ALL,
    A,
    AAAA,
    AFSDB,
    APL,
    CAA,
    CDNSKEY,
    CDS,
    CERT,
    CNAME,
    CSYNC,
    DHCID,
    DNAME,
    DNSKEY,
    DS,
    EUI48,
    EUI64,
    HINFO,
    HIP,
    HTTPS,
    IPSECKEY,
    KEY,
    KX,
    LOC,
    MX,
    NAPTR,
    NS,
    NSEC,
    NSEC3,
    NSEC3PARAM,
    OPENPGPKEY,
    PTR,
    RP,
    RRSIG,
    SIG,
    SMIMEA,
    SOA,
    SRV,
    SSHFP,
    SVCB,
    TKEY,
    TLSA,
    TSIG,
    TXT,
    URI,
    ZONEMD,
}

impl Targets {
    fn octets(&self) -> [u8; 2] {
        match self {
            Self::ALL => [0, 255],
            Self::A => [0, 1],
            Self::AAAA => [0, 28],
            Self::AFSDB => [0, 18],
            Self::APL => [0, 42],
            Self::CAA => [1, 1],
            Self::CDNSKEY => [0, 60],
            Self::CDS => [0, 59],
            Self::CERT => [0, 37],
            Self::CNAME => [0, 5],
            Self::CSYNC => [0, 62],
            Self::DHCID => [0, 49],
            Self::DNAME => [0, 39],
            Self::DNSKEY => [0, 48],
            Self::DS => [0, 43],
            Self::EUI48 => [0, 108],
            Self::EUI64 => [0, 109],
            Self::HINFO => [0, 13],
            Self::HIP => [0, 55],
            Self::HTTPS => [0, 65],
            Self::IPSECKEY => [0, 45],
            Self::KEY => [0, 25],
            Self::KX => [0, 36],
            Self::LOC => [0, 29],
            Self::MX => [0, 15],
            Self::NAPTR => [0, 35],
            Self::NS => [0, 2],
            Self::NSEC => [0, 47],
            Self::NSEC3 => [0, 50],
            Self::NSEC3PARAM => [0, 51],
            Self::OPENPGPKEY => [0, 61],
            Self::PTR => [0, 12],
            Self::RP => [0, 17],
            Self::RRSIG => [0, 46],
            Self::SIG => [0, 24],
            Self::SMIMEA => [0, 53],
            Self::SOA => [0, 6],
            Self::SRV => [0, 33],
            Self::SSHFP => [0, 44],
            Self::SVCB => [0, 64],
            Self::TKEY => [0, 249],
            Self::TLSA => [0, 52],
            Self::TSIG => [0, 250],
            Self::TXT => [0, 16],
            Self::URI => [1, 0],
            Self::ZONEMD => [0, 63],
        }
    }
}

fn gen_resp_v4(buff: &[u8], resp: &mut Buffering, ip: &Ipv4Addr) -> bool {
    if buff[2..12] == [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        && buff[buff.len() - 4..buff.len() - 2] == [0, 1]
    {
        resp.write(buff)
            .mutate(7, 1)
            .mutate(2, 133)
            .write(&buff[12..])
            .write(&[0, 0, 0, 20, 0, 4])
            .write(&ip.octets());

        return true;
    }
    false
}

fn gen_resp_v6(buff: &[u8], resp: &mut Buffering, ip: &Ipv6Addr) -> bool {
    if buff[2..12] == [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        && buff[buff.len() - 4..buff.len() - 2] == [0, 28]
    {
        resp.write(buff)
            .mutate(7, 1)
            .mutate(2, 133)
            .write(&buff[12..])
            .write(&[0, 0, 0, 20, 0, 16])
            .write(&ip.octets());

        return true;
    }
    false
}
