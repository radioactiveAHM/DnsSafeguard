#[derive(serde::Deserialize)]
pub struct Fragmenting {
    pub enable: bool,
    pub method: String,
}

#[derive(serde::Deserialize)]
pub struct Ipv6 {
    pub enable: bool,
    pub http_version: u8,
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
    pub fragmenting: Fragmenting,
}

#[derive(serde::Deserialize)]
#[derive(Clone)]
pub struct Quic {
    pub congestion_controller: String,
    pub keep_alive_interval: u64,
    pub datagram_receive_buffer_size: usize,
    pub datagram_send_buffer_size: usize
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub http_version: u8,
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
    pub fragmenting: Fragmenting,
    pub ipv6: Ipv6,
    pub quic: Quic
}

pub fn load_config() -> Config {
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
