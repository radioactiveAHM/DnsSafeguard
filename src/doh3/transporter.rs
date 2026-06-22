pub fn tc(quic_conf: &crate::config::Quic) -> std::sync::Arc<quinn::TransportConfig> {
	let mut transport_config = quinn::TransportConfig::default();

	transport_config.keep_alive_interval(quic_conf.keep_alive_interval.map(std::time::Duration::from_secs));
	transport_config.congestion_controller_factory(congestion_selection(quic_conf.congestion_controller));
	transport_config.datagram_receive_buffer_size(quic_conf.datagram_receive_buffer_size);
	transport_config.datagram_send_buffer_size(quic_conf.datagram_send_buffer_size);
	transport_config.packet_threshold(quic_conf.packet_threshold);
	transport_config.max_idle_timeout(
		quic_conf
			.max_idle_timeout
			.map(|max_idle_timeout| std::time::Duration::from_secs(max_idle_timeout).try_into().unwrap()),
	);
	transport_config.initial_mtu(quic_conf.initial_mtu);
	transport_config.min_mtu(quic_conf.min_mtu);
	transport_config.crypto_buffer_size(quic_conf.crypto_buffer_size);
	transport_config.stream_receive_window(quic_conf.stream_receive_window.into());
	transport_config.receive_window(quic_conf.receive_window.into());
	transport_config.send_window(quic_conf.send_window);
	transport_config.send_fairness(quic_conf.fairness);
	transport_config.max_concurrent_bidi_streams(quic_conf.max_streams.into());

	std::sync::Arc::new(transport_config)
}

fn congestion_selection(
	congestion_controller: crate::config::CongestionController,
) -> std::sync::Arc<dyn quinn::congestion::ControllerFactory + Send + Sync + 'static> {
	match congestion_controller {
		crate::config::CongestionController::cubic => std::sync::Arc::new(quinn::congestion::CubicConfig::default()),
		crate::config::CongestionController::bbr => std::sync::Arc::new(quinn::congestion::BbrConfig::default()),
		crate::config::CongestionController::newreno => {
			std::sync::Arc::new(quinn::congestion::NewRenoConfig::default())
		}
	}
}
