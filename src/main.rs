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
mod keepalive;
mod rule;
mod tls;
mod udp;
mod utils;

static CONFIG: std::sync::LazyLock<config::Config> = std::sync::LazyLock::new(config::load_config);

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    {
        let mut logger = env_logger::builder();
        #[cfg(not(debug_assertions))]
        {
            if let Some(file) = &CONFIG.log.file {
                logger.target(env_logger::Target::Pipe(Box::new(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(file)
                        .unwrap(),
                )));
            }
        }
        // Level order: Error, Warn, Info, Debug, Trace
        logger.filter_level(CONFIG.log.level.convert()).init();
    }

    // Log panic info
    std::panic::set_hook(Box::new(|message| {
        log::error!("{message}");
    }));

    if CONFIG.doh_server.enable {
        tokio::spawn(dohserver::doh_server(
            &CONFIG.doh_server,
            CONFIG.serve_addrs,
        ));
    }

    match CONFIG.protocol {
        config::Protocol::h1_multi => h11::h1_multi().await,
        config::Protocol::h1 => h11::http1().await,
        config::Protocol::h2 => doh2::http2().await,
        config::Protocol::h3 => doh3::http3().await,
        config::Protocol::dot => dot::dot().await,
        config::Protocol::doq => doq::doq().await,
    };
}
