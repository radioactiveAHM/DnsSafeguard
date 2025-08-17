#![forbid(unsafe_code)]

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

static CONFIG: std::sync::LazyLock<config::Config> = std::sync::LazyLock::new(config::load_config);

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    // Level order: Error, Warn, Info, Debug, Trace
    if let Some(file) = &CONFIG.log.file {
        env_logger::builder()
            .target(env_logger::Target::Pipe(Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file)
                    .unwrap(),
            )))
            .filter_level(CONFIG.log.level.convert())
            .init();
    } else {
        env_logger::builder()
        .filter_level(CONFIG.log.level.convert())
        .init();
    }

    // Log panic info
    std::panic::set_hook(Box::new(|message| {
        log::error!("{message}");
    }));

    if CONFIG.doh_server.enable {
        tokio::spawn(async move {
            dohserver::doh_server(&CONFIG.doh_server, CONFIG.serve_addrs).await;
        });
    }

    let converted_rules = std::sync::Arc::new(convert_rules(&CONFIG.rules));

    match CONFIG.protocol {
        config::Protocol::h1_multi => h1_multi(converted_rules).await,
        config::Protocol::h1 => http1(converted_rules).await,
        config::Protocol::h2 => doh2::http2(converted_rules).await,
        config::Protocol::h3 => doh3::http3(converted_rules).await,
        config::Protocol::dot => dot::dot(converted_rules).await,
        config::Protocol::doq => doq::doq(converted_rules).await,
    };
}
