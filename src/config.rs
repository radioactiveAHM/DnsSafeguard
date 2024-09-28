#[derive(serde::Deserialize, Clone)]
pub struct Fragmenting {
    pub enable: bool,
    pub method: String,
}

#[derive(serde::Deserialize, Clone)]
pub struct Noise {
    pub enable: bool,
    pub packet_length: usize,
    pub packets: u8,
    pub sleep: u64,
    pub ntype: String,
    pub content: String,
    pub continues: bool
}

#[derive(serde::Deserialize)]
pub struct Ipv6 {
    pub enable: bool,
    pub protocol: String,
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
    pub fragmenting: Fragmenting,
    pub noise: Noise,
}

#[derive(serde::Deserialize, Clone)]
pub struct Quic {
    pub congestion_controller: String,
    pub keep_alive_interval: u64,
    pub datagram_receive_buffer_size: usize,
    pub datagram_send_buffer_size: usize,
    pub connecting_timeout_sec: u64
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub protocol: String,
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
    pub fragmenting: Fragmenting,
    pub noise: Noise,
    pub ipv6: Ipv6,
    pub quic: Quic,
    pub connections: u8,
}

pub fn load_config() -> Config {
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
