#![forbid(unsafe_code)]

mod chttp;
mod config;
mod disconnected;
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
mod win;

static CONFIG: std::sync::LazyLock<config::Config> = std::sync::LazyLock::new(config::load_config);

fn main() {
	// windows service pipe
	#[cfg(target_os = "windows")]
	{
		use win::service::win_service_controller;
		windows_service::define_windows_service!(ffi_service_main, win_service_controller);
		std::thread::spawn(|| windows_service::service_dispatcher::start("DnsSafeguard", ffi_service_main));
	}

	match CONFIG.runtime.runtime_mode {
		config::RuntimeMode::Multi => {
			let mut r = tokio::runtime::Builder::new_multi_thread();

			if let Some(worker_threads) = CONFIG.runtime.worker_threads {
				r.worker_threads(worker_threads);
			}
			if let Some(thread_stack_size) = CONFIG.runtime.thread_stack_size {
				r.thread_stack_size(thread_stack_size);
			}
			if let Some(event_interval) = CONFIG.runtime.event_interval {
				r.event_interval(event_interval);
			}
			if let Some(global_queue_interval) = CONFIG.runtime.global_queue_interval {
				r.global_queue_interval(global_queue_interval);
			}
			if let Some(thread_keep_alive) = CONFIG.runtime.thread_keep_alive {
				r.thread_keep_alive(std::time::Duration::from_secs(thread_keep_alive));
			}

			r
		}
		config::RuntimeMode::Single => {
			let mut r = tokio::runtime::Builder::new_current_thread();

			if let Some(thread_stack_size) = CONFIG.runtime.thread_stack_size {
				r.thread_stack_size(thread_stack_size);
			}
			if let Some(event_interval) = CONFIG.runtime.event_interval {
				r.event_interval(event_interval);
			}
			if let Some(global_queue_interval) = CONFIG.runtime.global_queue_interval {
				r.global_queue_interval(global_queue_interval);
			}
			if let Some(thread_keep_alive) = CONFIG.runtime.thread_keep_alive {
				r.thread_keep_alive(std::time::Duration::from_secs(thread_keep_alive));
			}
			if let Some(max_io_events_per_tick) = CONFIG.runtime.max_io_events_per_tick {
				r.max_io_events_per_tick(max_io_events_per_tick);
			}

			r
		}
	}
	.enable_all()
	.build()
	.unwrap()
	.block_on(app());
}

async fn app() {
	if let Some(level) = &CONFIG.log.level {
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
		logger.filter_level(level.into()).init();
	}

	// Set log level to trace which is required for tracing to work fine
	log::set_max_level(log::LevelFilter::Trace);

	// Log panic info
	std::panic::set_hook(Box::new(|message| {
		log::error!("{message}");
	}));

	if CONFIG.doh_server.enable {
		tokio::spawn(dohserver::doh_server(&CONFIG.doh_server, CONFIG.serve_addrs));
	}

	match CONFIG.protocol {
		config::Protocol::h1_multi => tokio::spawn(h11::h1_multi()),
		config::Protocol::h1 => tokio::spawn(h11::http1()),
		config::Protocol::h2 => tokio::spawn(doh2::http2()),
		config::Protocol::h3 => tokio::spawn(doh3::http3()),
		config::Protocol::dot => tokio::spawn(dot::dot()),
		config::Protocol::doq => tokio::spawn(doq::doq()),
	};

	std::future::pending::<()>().await
}
