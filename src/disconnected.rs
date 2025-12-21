#[derive(Clone)]
pub struct Disconnected(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Disconnected {
	pub fn new() -> Self {
		Self(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)))
	}

	pub fn get(&self) -> bool {
		self.0.load(std::sync::atomic::Ordering::Acquire)
	}

	pub fn disconnect(&self) {
		self.0.store(true, std::sync::atomic::Ordering::Release);
	}

	pub fn connect(&self) {
		self.0.store(false, std::sync::atomic::Ordering::Release);
	}
}
