use quinn::{IdleTimeout, VarInt};

pub fn tc(quic_conf: &crate::config::Quic) -> std::sync::Arc<quinn::TransportConfig> {
	let mut transport_config = quinn::TransportConfig::default();

	transport_config.keep_alive_interval(quic_conf.keep_alive_interval.map(std::time::Duration::from_secs));
	transport_config.congestion_controller_factory(congestion_selection(quic_conf.congestion_controller));
	transport_config.datagram_receive_buffer_size(quic_conf.datagram_receive_buffer_size);
	if let Some(datagram_send_buffer_size) = quic_conf.datagram_send_buffer_size {
		transport_config.datagram_send_buffer_size(datagram_send_buffer_size);
	}
	transport_config.packet_threshold(quic_conf.packet_threshold);
	transport_config.max_idle_timeout(
		quic_conf
			.max_idle_timeout
			.map(|max_idle_timeout| IdleTimeout::from(VarInt::from_u32(max_idle_timeout * 1000))),
	);
	if let Some(initial_mtu) = quic_conf.initial_mtu {
		transport_config.initial_mtu(initial_mtu);
	}
	if let Some(min_mtu) = quic_conf.min_mtu {
		transport_config.min_mtu(min_mtu);
	}
	if let Some(crypto_buffer_size) = quic_conf.crypto_buffer_size {
		transport_config.crypto_buffer_size(crypto_buffer_size);
	}
	if let Some(stream_receive_window) = quic_conf.stream_receive_window {
		transport_config.stream_receive_window(VarInt::from_u32(stream_receive_window));
	}

	std::sync::Arc::new(transport_config)
}

fn congestion_selection(
	congestion_controller: crate::config::CongestionController,
) -> std::sync::Arc<dyn quinn::congestion::ControllerFactory + Send + Sync + 'static> {
	match congestion_controller {
		crate::config::CongestionController::bbr => std::sync::Arc::new(quinn::congestion::BbrConfig::default()),
		crate::config::CongestionController::cubic => std::sync::Arc::new(quinn::congestion::CubicConfig::default()),
		crate::config::CongestionController::newreno => {
			std::sync::Arc::new(quinn::congestion::NewRenoConfig::default())
		}
	}
}
