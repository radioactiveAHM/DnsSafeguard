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
mod ioutils;
mod ipoverwrite;
mod multi;
mod rule;
mod tls;
mod udp;
mod utils;

use h11::http1;
use multi::h1_multi;
use rule::convert_rules;
use utils::unsafe_staticref;

static mut SOCKET_OPT: config::TcpSocketOptions = config::TcpSocketOptions {
    send_buffer_size: None,
    recv_buffer_size: None,
    nodelay: None,
    keepalive: None,
    linux: config::LinuxSocketOptions {
        bind_to_device: None,
        mss: None,
        congestion: None,
    },
};

// I will change this later
#[allow(static_mut_refs)]
fn get_socket_op() -> &'static config::TcpSocketOptions {
    unsafe { &SOCKET_OPT }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let conf = config::load_config();

    // Setup LOG
    unsafe {
        std::env::set_var("RUST_LOG", &conf.log);
    }
    // Level order: Error, Warn, Info, Debug, Trace
    env_logger::init();

    // Convert rules to adjust domains like dns query and improve performance
    let rules = convert_rules(&conf.rules);

    unsafe { SOCKET_OPT = conf.tcp_socket_options.clone() }

    // values all avalible during application lifetime
    let urules = unsafe_staticref(&rules);
    let config: &'static config::Config = unsafe_staticref(&conf);

    if conf.doh_server.enable {
        tokio::spawn(async move {
            dohserver::doh_server(conf.doh_server, conf.serve_addrs).await;
        });
    }

    match conf.protocol {
        config::Protocol::h1_multi => h1_multi(config, urules).await,
        config::Protocol::h1 => http1(config, rules).await,
        config::Protocol::h2 => doh2::http2(config, urules).await,
        config::Protocol::h3 => doh3::http3(config, urules).await,
        config::Protocol::dot => {
            dot::dot(config, urules).await;
        }
        config::Protocol::doq => {
            doq::doq(config, urules).await;
        }
    }
}
