#[cfg(target_os = "windows")]
pub mod service {
	use windows_service::{
		service::{ServiceControl, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
		service_control_handler::{self, ServiceControlHandlerResult},
	};

	pub fn win_service_controller(_arguments: Vec<std::ffi::OsString>) {
		let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
		let stop_clone = stop.clone();
		let handler = service_control_handler::register("DnsSafeguard", move |control_event| {
			match control_event {
				ServiceControl::Stop => {
					// Handle stop
					stop_clone.store(true, std::sync::atomic::Ordering::Release);
					ServiceControlHandlerResult::NoError
				}
				_ => ServiceControlHandlerResult::NotImplemented,
			}
		})
		.unwrap();

		handler
			.set_service_status(ServiceStatus {
				process_id: None,
				service_type: ServiceType::OWN_PROCESS,
				current_state: ServiceState::Running,
				controls_accepted: windows_service::service::ServiceControlAccept::STOP,
				exit_code: ServiceExitCode::Win32(0),
				checkpoint: 0,
				wait_hint: std::time::Duration::default(),
			})
			.unwrap();

		loop {
			std::thread::sleep(std::time::Duration::from_secs(5));
			if stop.load(std::sync::atomic::Ordering::Acquire) {
				handler
					.set_service_status(ServiceStatus {
						process_id: None,
						service_type: ServiceType::OWN_PROCESS,
						current_state: ServiceState::Stopped,
						controls_accepted: windows_service::service::ServiceControlAccept::empty(),
						exit_code: ServiceExitCode::Win32(0),
						checkpoint: 1,
						wait_hint: std::time::Duration::default(),
					})
					.unwrap();
				std::process::exit(0);
			}
		}
	}
}
