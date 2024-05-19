#[derive(serde::Deserialize)]
pub struct Ipv6 {
    pub enable: bool,
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
    pub fragment_method: String
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
    pub fragment_method: String,
    pub ipv6: Ipv6
}

pub fn load_config() -> Config {
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
