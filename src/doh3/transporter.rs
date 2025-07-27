use quinn::{IdleTimeout, VarInt};

pub fn tc(quic_conf: &crate::config::Quic) -> std::sync::Arc<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();

    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(
        quic_conf.keep_alive_interval,
    )));
    transport_config
        .congestion_controller_factory(congestion_selection(quic_conf.congestion_controller));
    transport_config.datagram_receive_buffer_size(quic_conf.datagram_receive_buffer_size);
    if let Some(datagram_send_buffer_size) = quic_conf.datagram_send_buffer_size {
        transport_config.datagram_send_buffer_size(datagram_send_buffer_size);
    }
    transport_config.packet_threshold(quic_conf.packet_threshold);
    if let Some(max_idle_timeout) = quic_conf.max_idle_timeout {
        transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
            max_idle_timeout * 1000,
        ))));
    } else {
        transport_config.max_idle_timeout(None);
    }

    std::sync::Arc::new(transport_config)
}

fn congestion_selection(
    congestion_controller: crate::config::CongestionController,
) -> std::sync::Arc<dyn quinn::congestion::ControllerFactory + Send + Sync + 'static> {
    match congestion_controller {
        crate::config::CongestionController::bbr => {
            std::sync::Arc::new(quinn::congestion::BbrConfig::default())
        }
        crate::config::CongestionController::cubic => {
            std::sync::Arc::new(quinn::congestion::CubicConfig::default())
        }
        crate::config::CongestionController::newreno => {
            std::sync::Arc::new(quinn::congestion::NewRenoConfig::default())
        }
    }
}
