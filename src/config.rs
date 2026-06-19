#[derive(serde::Deserialize, Clone)]
pub struct TcpSocketOptions {
	pub send_buffer_size: Option<u32>,
	pub recv_buffer_size: Option<u32>,
	pub nodelay: Option<bool>,
	pub keepalive: Option<bool>,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum FragMethod {
	random,
	single,
}

#[derive(serde::Deserialize, Clone)]
pub struct Fragmenting {
	pub enable: bool,
	pub method: FragMethod,
	pub sleep_interval: String,
	pub fragment_size: String,
	pub segments: usize,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum NoiseType {
	dns,
	str,
	lsd,
	rand,
	tracker,
	stun,
	tftp,
	ntp,
	socks5,
	turn,
	dht,
}

#[derive(serde::Deserialize)]
pub struct Noise {
	pub ntype: NoiseType,
	pub content: String,
	pub size: String,
	pub sleep: u64,
}

#[derive(serde::Deserialize)]
pub struct Noiser {
	pub enable: bool,
	pub noises: Vec<Noise>,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Protocol {
	h1,
	h2,
	h3,
	dot,
	doq,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum CongestionController {
	bbr,
	cubic,
	newreno,
}

#[derive(serde::Deserialize, Clone)]
pub struct Quic {
	pub congestion_controller: CongestionController,
	pub keep_alive_interval: Option<u64>,
	pub connecting_timeout: u64,
	pub datagram_receive_buffer_size: Option<usize>,
	pub datagram_send_buffer_size: Option<usize>,
	pub packet_threshold: u32,
	pub initial_mtu: Option<u16>,
	pub min_mtu: Option<u16>,
	pub crypto_buffer_size: Option<usize>,
	pub stream_receive_window: Option<u32>,
	pub max_idle_timeout: Option<u64>,
}

#[derive(serde::Deserialize, Clone)]
pub struct H2 {
	pub header_table_size: u32,
	pub max_header_list_size: u32,
	pub initial_connection_window_size: u32,
	pub initial_window_size: u32,
	pub max_pending_accept_reset_streams: usize,
	pub max_concurrent_reset_streams: usize,
	pub max_frame_size: u32,
}

#[derive(serde::Deserialize, Clone)]
#[allow(non_camel_case_types)]
pub enum TargetType {
	block(Option<Vec<crate::rule::Targets>>),
	ip(std::net::IpAddr, Option<std::net::Ipv6Addr>),
}

#[derive(serde::Deserialize)]
pub struct DohServer {
	pub enable: bool,
	pub alpn: Vec<String>,
	pub listen_address: std::net::SocketAddr,
	pub certificate: std::path::PathBuf,
	pub key: std::path::PathBuf,
	pub cache_control: String,
	pub response_timeout: u64,
	pub log_errors: bool,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpMethod {
	POST,
	GET,
}

#[derive(serde::Deserialize)]
#[allow(non_camel_case_types)]
pub enum LevelFilter {
	error,
	warn,
	info,
	debug,
	trace,
}

impl LevelFilter {
	pub const fn into(&self) -> log::LevelFilter {
		match self {
			Self::error => log::LevelFilter::Error,
			Self::warn => log::LevelFilter::Warn,
			Self::info => log::LevelFilter::Info,
			Self::debug => log::LevelFilter::Debug,
			Self::trace => log::LevelFilter::Trace,
		}
	}
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct Log {
	pub level: Option<LevelFilter>,
	pub file: Option<std::path::PathBuf>,
}

#[derive(serde::Deserialize)]
pub enum RuntimeMode {
	Single,
	Multi,
}

#[derive(serde::Deserialize)]
#[allow(non_camel_case_types)]
pub enum TlsCore {
	rustls,
	boring,
	native,
}

#[derive(serde::Deserialize)]
pub struct Runtime {
	pub runtime_mode: RuntimeMode,
	pub worker_threads: Option<usize>,
	pub thread_stack_size: Option<usize>,
	pub event_interval: Option<u32>,
	pub global_queue_interval: Option<u32>,
	pub max_io_events_per_tick: Option<usize>,
	pub thread_keep_alive: Option<u64>,
}

#[derive(serde::Deserialize)]
pub struct Server {
	pub id: String,
	pub protocol: Protocol,
	pub remote_addrs: Vec<std::net::SocketAddr>,
	pub hostname: String,
	pub path: String,
	pub http_method: HttpMethod,
	pub sni: String,
	pub ip_as_sni: bool,
	pub disable_certificate_validation: bool,
}

#[derive(serde::Deserialize)]
pub struct Config {
	pub log: Log,
	pub servers: Vec<Server>,
	pub serve_addrs: std::net::SocketAddr,
	pub interface: Option<String>,
	pub response_timeout: u64,
	pub connection_keep_alive: Option<u64>,
	pub pipe_capacity: usize,
	pub tls_core: TlsCore,
	pub fragmenting: Fragmenting,
	pub noiser: Noiser,
	pub quic: Quic,
	pub h2: H2,
	pub reconnect_sleep: u64,
	pub tcp_socket_options: TcpSocketOptions,
	pub doh_server: DohServer,
	pub runtime: Runtime,
	#[serde(deserialize_with = "crate::rule::deserialize_rule")]
	pub rules: Option<Vec<crate::rule::Rule>>,
	pub overwrite: Option<Vec<crate::ipoverwrite::IpOverwrite>>,
}

pub fn load_config() -> Config {
	if let Ok(mut p) = std::env::current_exe()
		&& p.pop()
	{
		#[cfg(not(debug_assertions))]
		{
			let _ = std::env::set_current_dir(&p);
		}
		let c = p.join("config.json");
		if c.exists() {
			let config_file = std::fs::read(c).expect("can not read config file");
			let conf: Config = serde_json::from_slice(&config_file).expect("malformed config file");
			return conf;
		}
	}
	let config_file = std::fs::read("config.json").expect("can not read config file");
	let conf: Config = serde_json::from_slice(&config_file).expect("malformed config file");
	conf
}
