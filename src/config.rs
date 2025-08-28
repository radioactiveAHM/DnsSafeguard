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
    syslog,
}

#[derive(serde::Deserialize)]
pub struct Noise {
    pub enable: bool,
    pub packet_length: String,
    pub packets: u8,
    pub sleep: u64,
    pub ntype: NoiseType,
    pub content: String,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Protocol {
    h1,
    h1_multi,
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
    pub keep_alive_interval: u64,
    pub connecting_timeout: u64,
    pub datagram_receive_buffer_size: Option<usize>,
    pub datagram_send_buffer_size: Option<usize>,
    pub packet_threshold: u32,
    pub max_idle_timeout: Option<u32>,
}

#[derive(serde::Deserialize, Clone, Copy)]
pub struct Connection {
    pub h1_multi_connections: usize,
    pub reconnect_sleep: u64,
}

#[derive(serde::Deserialize, Clone)]
#[allow(non_camel_case_types)]
pub enum TargetType {
    dns(std::net::SocketAddr),
    block(Option<Vec<crate::rule::Targets>>),
    ip(std::net::IpAddr, Option<std::net::Ipv6Addr>),
}

#[derive(serde::Deserialize, Clone)]
pub struct Rule {
    pub options: Vec<String>,
    pub target: TargetType,
}

#[derive(serde::Deserialize)]
pub struct DohServer {
    pub enable: bool,
    pub alpn: Vec<String>,
    pub listen_address: std::net::SocketAddr,
    pub certificate: std::path::PathBuf,
    pub key: std::path::PathBuf,
    pub cache_control: String,
    pub response_timeout: (u64, u64),
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
    off,
    error,
    warn,
    info,
    debug,
    trace,
}

impl LevelFilter {
    pub fn convert(&self) -> log::LevelFilter {
        match self {
            Self::off => log::LevelFilter::Off,
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
    pub level: LevelFilter,
    pub file: Option<std::path::PathBuf>,
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub log: Log,
    pub protocol: Protocol,
    pub server_name: String,
    pub ip_as_sni: bool,
    pub disable_certificate_validation: bool,
    pub remote_addrs: std::net::SocketAddr,
    pub interface: Option<String>,
    pub serve_addrs: std::net::SocketAddr,
    pub custom_http_path: Option<String>,
    pub response_timeout: u64,
    pub http_method: HttpMethod,
    pub connection_keep_alive: Option<u64>,
    pub native_tls: bool,
    pub fragmenting: Fragmenting,
    pub noise: Noise,
    pub quic: Quic,
    pub connection: Connection,
    pub tcp_socket_options: TcpSocketOptions,
    pub doh_server: DohServer,
    pub rules: Option<Vec<Rule>>,
    pub overwrite: Option<Vec<crate::ipoverwrite::IpOverwrite>>,
}

pub fn load_config() -> Config {
    if let Ok(mut p) = std::env::current_exe()
        && p.pop()
    {
        let c = p.join("config.json");
        if c.exists() {
            let config_file = std::fs::read(c).expect("Can not read config file");
            let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
            return conf;
        }
    }
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
