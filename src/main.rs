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
mod multi;
mod rule;
mod tls;
mod utils;

use h11::http1;
use multi::h1_multi;
use rule::{convert_rules, Rules};
use utils::Sni;

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

    if conf.doh_server.enable {
        tokio::spawn(async move {
            dohserver::doh_server(conf.doh_server, conf.udp_socket_addrs).await;
        });
    }

    let v6 = conf.ipv6;
    let quic_conf_file_v6 = conf.quic.clone();
    let v6rules = rules.clone();
    tokio::spawn(async move {
        if v6.enable {
            match v6.protocol {
                config::Protocol::h1_multi => {
                    h1_multi(
                        Sni::new(v6.server_name),
                        v6.disable_domain_sni,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                        v6.custom_http_path,
                    )
                    .await
                }
                config::Protocol::h1 => {
                    http1(
                        Sni::new(v6.server_name),
                        v6.disable_domain_sni,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                        v6.custom_http_path,
                    )
                    .await
                }
                config::Protocol::h2 => {
                    doh2::http2(
                        Sni::new(v6.server_name),
                        v6.disable_domain_sni,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                        v6.custom_http_path,
                    )
                    .await
                }
                config::Protocol::h3 => {
                    let connecting_timeout_sec = quic_conf_file_v6.connecting_timeout_sec;
                    doh3::http3(
                        Sni::new(v6.server_name),
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        quic_conf_file_v6,
                        v6.noise,
                        connecting_timeout_sec,
                        conf.connection,
                        v6rules,
                        v6.custom_http_path,
                    )
                    .await
                }
                config::Protocol::dot => {
                    dot::dot(
                        Sni::new(v6.server_name),
                        v6.disable_domain_sni,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await;
                }
                config::Protocol::dot_nonblocking => {
                    dot::dot_nonblocking(
                        Sni::new(v6.server_name),
                        v6.disable_domain_sni,
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        &v6.fragmenting,
                        conf.connection,
                        v6rules,
                    )
                    .await;
                }
                config::Protocol::doq => {
                    let connecting_timeout_sec = quic_conf_file_v6.connecting_timeout_sec;
                    doq::doq(
                        Sni::new(v6.server_name),
                        v6.socket_addrs,
                        v6.udp_socket_addrs,
                        quic_conf_file_v6,
                        v6.noise,
                        connecting_timeout_sec,
                        conf.connection,
                        v6rules,
                    )
                    .await;
                }
            }
        }
    });

    match conf.protocol {
        config::Protocol::h1_multi => {
            h1_multi(
                Sni::new(conf.server_name),
                conf.disable_domain_sni,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
                conf.custom_http_path,
            )
            .await
        }
        config::Protocol::h1 => {
            http1(
                Sni::new(conf.server_name),
                conf.disable_domain_sni,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
                conf.custom_http_path,
            )
            .await
        }
        config::Protocol::h2 => {
            doh2::http2(
                Sni::new(conf.server_name),
                conf.disable_domain_sni,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
                conf.custom_http_path,
            )
            .await
        }
        config::Protocol::h3 => {
            let connecting_timeout_sec = conf.quic.connecting_timeout_sec;
            doh3::http3(
                Sni::new(conf.server_name),
                conf.socket_addrs,
                conf.udp_socket_addrs,
                conf.quic,
                conf.noise,
                connecting_timeout_sec,
                conf.connection,
                rules,
                conf.custom_http_path,
            )
            .await
        }
        config::Protocol::dot => {
            dot::dot(
                Sni::new(conf.server_name),
                conf.disable_domain_sni,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await;
        }
        config::Protocol::dot_nonblocking => {
            dot::dot_nonblocking(
                Sni::new(conf.server_name),
                conf.disable_domain_sni,
                conf.socket_addrs,
                conf.udp_socket_addrs,
                &conf.fragmenting,
                conf.connection,
                rules,
            )
            .await;
        }
        config::Protocol::doq => {
            let connecting_timeout_sec = conf.quic.connecting_timeout_sec;
            doq::doq(
                Sni::new(conf.server_name),
                conf.socket_addrs,
                conf.udp_socket_addrs,
                conf.quic,
                conf.noise,
                connecting_timeout_sec,
                conf.connection,
                rules,
            )
            .await;
        }
    }
}
