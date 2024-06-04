use std::sync::Arc;

pub fn tc(quic_conf_file: crate::config::Quic) -> Arc<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();

    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(quic_conf_file.keep_alive_interval)));

    transport_config.congestion_controller_factory(congestion_selection(quic_conf_file.congestion_controller));

    transport_config.datagram_receive_buffer_size(Some(quic_conf_file.datagram_receive_buffer_size));

    transport_config.datagram_send_buffer_size(quic_conf_file.datagram_send_buffer_size);

    Arc::new(transport_config)
}

fn congestion_selection (congestion_controller: String) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync + 'static> {
    match congestion_controller.as_str() {
        "bbr"=> Arc::new(quinn::congestion::BbrConfig::default()),
        "cubic"=> Arc::new(quinn::congestion::CubicConfig::default()),
        "newreno"=> Arc::new(quinn::congestion::NewRenoConfig::default()),
        _=> {
            print!("Invalid congestion controller");
            panic!()
        }
    }
}