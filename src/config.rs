use std::net::SocketAddr;

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum FragMethod {
    linear,
    random,
    single,
    jump,
}

#[derive(serde::Deserialize, Clone)]
pub struct Fragmenting {
    pub enable: bool,
    pub method: FragMethod,
    pub sleep_interval_min: u64,
    pub sleep_interval_max: u64
}

#[derive(serde::Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum NoiseType {
    dns,
    str,
    lsd,
    rand,
}

#[derive(serde::Deserialize, Clone)]
pub struct Noise {
    pub enable: bool,
    pub packet_length: usize,
    pub packets: u8,
    pub sleep: u64,
    pub ntype: NoiseType,
    pub content: String,
    pub continues: bool,
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
    pub socket_addrs: SocketAddr,
    pub udp_socket_addrs: SocketAddr,
    pub custom_http_path: Option<String>,
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
pub struct Rule {
    pub options: Vec<String>,
    pub target: String,
}

#[derive(serde::Deserialize)]
pub struct DohServer {
    pub enable: bool,
    pub alpn: Vec<String>,
    pub listen_address: SocketAddr,
    pub certificate: String,
    pub key: String,
    pub log_errors: bool,
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub protocol: Protocol,
    pub server_name: String,
    pub disable_domain_sni: bool,
    pub socket_addrs: SocketAddr,
    pub udp_socket_addrs: SocketAddr,
    pub custom_http_path: Option<String>,
    pub fragmenting: Fragmenting,
    pub noise: Noise,
    pub ipv6: Ipv6,
    pub quic: Quic,
    pub connection: Connection,
    pub doh_server: DohServer,
    pub rules: Option<Vec<Rule>>,
}

pub fn load_config() -> Config {
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
