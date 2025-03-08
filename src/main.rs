#![allow(clippy::too_many_arguments)]

mod chttp;
mod config;
mod doh2;
mod doh3;
mod dohserver;
mod doq;
mod dot;
mod fragment;
mod h11;
mod interface;
mod multi;
mod rule;
mod tls;
mod utils;

use h11::http1;
use multi::h1_multi;
use rule::{Rules, convert_rules};
use utils::unsafe_staticref;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    // Load config
    // If config file does not exist or malformed, panic occurs.
    let conf = config::load_config();
    // Convert rules to adjust domains like dns query and improve performance
    let rules = convert_rules(conf.rules);

    // unsafe values
    // since values all avalible during application lifetime
    let urules = unsafe_staticref(&rules);
    let usn = unsafe_staticref(conf.server_name.as_str());
    let ucpath = unsafe_staticref(&conf.custom_http_path);
    let network_interface = unsafe_staticref(&conf.interface);

    if conf.doh_server.enable {
        tokio::spawn(async move {
            dohserver::doh_server(conf.doh_server, conf.udp_socket_addrs).await;
        });
    }

    let v6 = conf.ipv6;

    // unsafe values
    // since values all avalible during application lifetime
    let usn6 = unsafe_staticref(v6.server_name.as_str());
    let ucpath6 = unsafe_staticref(&v6.custom_http_path);
    let network_interface6 = unsafe_staticref(&v6.interface);

    let quic_conf_file_v6 = conf.quic.clone();
    let v6rules = rules.clone();
    tokio::spawn(async move {
        if v6.enable {
            match v6.protocol {
                config::Protocol::h1_multi => {
                    h1_multi(
                        usn6,
                        v6.disable_domain_sni,
                        v6.disable_certificate_validation,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        urules,
                        ucpath6,
                        network_interface6,
                    )
                    .await
                }
                config::Protocol::h1 => {
                    http1(
                        usn6,
                        v6.disable_domain_sni,
                        v6.disable_certificate_validation,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                        ucpath6,
                        network_interface6,
                    )
                    .await
                }
                config::Protocol::h2 => {
                    doh2::http2(
                        usn6,
                        v6.disable_domain_sni,
                        v6.disable_certificate_validation,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        urules,
                        ucpath6,
                        network_interface6,
                    )
                    .await
                }
                config::Protocol::h3 => {
                    doh3::http3(
                        usn6,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        quic_conf_file_v6,
                        v6.noise,
                        conf.connection,
                        urules,
                        ucpath6,
                        network_interface6,
                    )
                    .await
                }
                config::Protocol::dot => {
                    dot::dot(
                        usn6,
                        v6.disable_domain_sni,
                        v6.disable_certificate_validation,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                        network_interface6,
                    )
                    .await;
                }
                config::Protocol::dot_nonblocking => {
                    dot::dot_nonblocking(
                        usn6,
                        v6.disable_domain_sni,
                        v6.disable_certificate_validation,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        urules,
                        network_interface6,
                    )
                    .await;
                }
                config::Protocol::doq => {
                    doq::doq(
                        usn6,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        quic_conf_file_v6,
                        v6.noise,
                        conf.connection,
                        urules,
                        network_interface6,
                    )
                    .await;
                }
            }
        }
    });

    match conf.protocol {
        config::Protocol::h1_multi => {
            h1_multi(
                usn,
                conf.disable_domain_sni,
                conf.disable_certificate_validation,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                urules,
                ucpath,
                network_interface,
            )
            .await
        }
        config::Protocol::h1 => {
            http1(
                usn,
                conf.disable_domain_sni,
                conf.disable_certificate_validation,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
                ucpath,
                network_interface,
            )
            .await
        }
        config::Protocol::h2 => {
            doh2::http2(
                usn,
                conf.disable_domain_sni,
                conf.disable_certificate_validation,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                urules,
                ucpath,
                network_interface,
            )
            .await
        }
        config::Protocol::h3 => {
            doh3::http3(
                usn,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                conf.quic,
                conf.noise,
                conf.connection,
                urules,
                ucpath,
                network_interface,
            )
            .await
        }
        config::Protocol::dot => {
            dot::dot(
                usn,
                conf.disable_domain_sni,
                conf.disable_certificate_validation,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
                network_interface,
            )
            .await;
        }
        config::Protocol::dot_nonblocking => {
            dot::dot_nonblocking(
                usn,
                conf.disable_domain_sni,
                conf.disable_certificate_validation,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                urules,
                network_interface,
            )
            .await;
        }
        config::Protocol::doq => {
            doq::doq(
                usn,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                conf.quic,
                conf.noise,
                conf.connection,
                urules,
                network_interface,
            )
            .await;
        }
    }
}
