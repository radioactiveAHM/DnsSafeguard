#[derive(serde::Deserialize, Clone, Copy)]
pub struct TcpSocketOptions {
    pub set_send_buffer_size: u32,
    pub set_recv_buffer_size: u32,
    pub nodelay: bool,
    pub keepalive: bool,
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
    tftp
}

#[derive(serde::Deserialize)]
pub struct Noise {
    pub enable: bool,
    pub packet_length: String,
    pub packets: u8,
    pub sleep: u64,
    pub ntype: NoiseType,
    pub content: String
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Protocol {
    h1,
    h1_multi,
    h2,
    h3,
    dot,
    dot_nonblocking,
    doq,
}

#[derive(serde::Deserialize)]
pub struct Ipv6 {
    pub enable: bool,
    pub protocol: Protocol,
    pub server_name: String,
    pub disable_domain_sni: bool,
    pub disable_certificate_validation: bool,
    pub socket_addrs: std::net::SocketAddr,
    pub interface: Option<String>,
    pub udp_socket_addrs: std::net::SocketAddr,
    pub custom_http_path: Option<String>,
    pub http_method: HttpMethod,
    pub fragmenting: Fragmenting,
    pub noise: Noise,
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
    pub datagram_receive_buffer_size: usize,
    pub datagram_send_buffer_size: usize,
    pub connecting_timeout_sec: u64,
    pub max_udp_payload_size: Option<u16>,
}

#[derive(serde::Deserialize, Clone, Copy)]
pub struct Connection {
    pub h1_multi_connections: u8,
    pub dot_nonblocking_dns_query_lifetime: u64,
    pub reconnect_sleep: u64,
    pub max_reconnect: u8,
    pub max_reconnect_sleep: u64,
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
    pub certificate: String,
    pub key: String,
    pub cache_control: String,
    pub log_errors: bool,
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpMethod {
    POST,
    GET,
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub protocol: Protocol,
    pub server_name: String,
    pub disable_domain_sni: bool,
    pub disable_certificate_validation: bool,
    pub socket_addrs: std::net::SocketAddr,
    pub interface: Option<String>,
    pub udp_socket_addrs: std::net::SocketAddr,
    pub custom_http_path: Option<String>,
    pub http_method: HttpMethod,
    pub fragmenting: Fragmenting,
    pub noise: Noise,
    pub ipv6: Ipv6,
    pub quic: Quic,
    pub connection: Connection,
    pub tcp_socket_options: TcpSocketOptions,
    pub doh_server: DohServer,
    pub rules: Option<Vec<Rule>>,
    pub overwrite: Option<Vec<crate::ipoverwrite::IpOverwrite>>,
}

pub fn load_config() -> Config {
    if let Ok(mut p) = std::env::current_exe() {
        if p.pop() {
            let c = p.join("config.json");
            if c.exists() {
                let config_file = std::fs::read(c).expect("Can not read config file");
                let conf: Config =
                    serde_json::from_slice(&config_file).expect("Malformed config file");
                return conf;
            }
        }
    }
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
