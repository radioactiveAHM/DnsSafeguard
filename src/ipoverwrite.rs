use std::net::{IpAddr, Ipv6Addr};

#[derive(serde::Deserialize)]
pub struct IpOverwrite {
    pub options: Vec<IpAddr>,
    pub target: (IpAddr, Option<Ipv6Addr>),
}

/// must check if ow is some
pub fn overwrite_ip(dns: &mut [u8], ow: &Option<Vec<crate::ipoverwrite::IpOverwrite>>) {
    // ignore if there is no ow setup
    let ow = ow.as_ref().unwrap();
    if ow.is_empty() {
        return;
    }

    for list in ow {
        for ip in &list.options {
            match ip {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    if let Some((a, b)) = crate::utils::catch_in_buff(&octets, dns)
                        && let IpAddr::V4(target) = list.target.0
                    {
                        dns[a..b].copy_from_slice(&target.octets());
                    }
                }
                IpAddr::V6(v6) => {
                    let octets = v6.octets();
                    if let Some((a, b)) = crate::utils::catch_in_buff(&octets, dns) {
                        if let IpAddr::V6(target) = list.target.0 {
                            dns[a..b].copy_from_slice(&target.octets());
                        } else if let Some(target6) = list.target.1 {
                            dns[a..b].copy_from_slice(&target6.octets());
                        }
                    }
                }
            }
        }
    }
}
