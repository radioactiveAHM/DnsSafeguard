#[derive(serde::Deserialize)]
pub struct Config {
    pub server_name: String,
    pub socket_addrs: String,
    pub udp_socket_addrs: String,
}

pub fn load_config() -> Config {
    let config_file = std::fs::read("config.json").expect("Can not read config file");
    let conf: Config = serde_json::from_slice(&config_file).expect("Malformed config file");
    conf
}
