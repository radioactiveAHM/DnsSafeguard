use bytes::Bytes;

pub enum Message {
	Udp(std::sync::Arc<tokio::net::UdpSocket>, std::net::SocketAddr, Vec<u8>),
	Doh(tokio::sync::oneshot::Sender<Bytes>, Bytes),
}

impl Message {
	#[inline(always)]
	pub async fn send_response(self, buf: Bytes) {
		match self {
			Self::Udp(udp, addr, _) => {
				let _ = udp.send_to(&buf, addr).await;
			}
			Self::Doh(oc, _) => {
				let _ = oc.send(buf);
			}
		}
	}
	#[inline(always)]
	pub async fn send_response_slice(self, buf: &[u8]) {
		match self {
			Self::Udp(udp, addr, _) => {
				let _ = udp.send_to(buf, addr).await;
			}
			Self::Doh(oc, _) => {
				let _ = oc.send(Bytes::copy_from_slice(buf));
			}
		}
	}
	#[inline(always)]
	pub fn message_slice(&self) -> &[u8] {
		match self {
			Self::Udp(_, _, b) => b,
			Self::Doh(_, b) => b,
		}
	}
}

#[derive(Clone)]
pub struct ReceiverPipe {
	receiver: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Message>>>,
}

impl ReceiverPipe {
	#[inline(always)]
	pub async fn recv_message(&self) -> Message {
		self.receiver.lock().await.recv().await.unwrap()
	}
}

// ----------------------

#[derive(Clone)]
pub struct SendPipe {
	sender: tokio::sync::mpsc::Sender<Message>,
}

impl SendPipe {
	#[inline(always)]
	pub async fn pipe_udp_message(self, udp: std::sync::Arc<tokio::net::UdpSocket>) {
		let mut buf = [0; 512];
		loop {
			if let Ok((size, addr)) = udp.recv_from(&mut buf).await {
				let cap = self.sender.reserve().await.unwrap();
				cap.send(Message::Udp(udp.clone(), addr, buf[..size].to_vec()));
			}
		}
	}

	#[inline(always)]
	pub async fn send_doh_message(&self, buf: Bytes) -> tokio::sync::oneshot::Receiver<Bytes> {
		let cap = self.sender.reserve().await.unwrap();
		let (sender, recver) = tokio::sync::oneshot::channel();
		cap.send(Message::Doh(sender, buf));
		recver
	}
}

// ----------------------

pub fn new_message_pipe(cap: usize) -> (SendPipe, ReceiverPipe) {
	let (s, r) = tokio::sync::mpsc::channel(cap);
	(
		SendPipe { sender: s },
		ReceiverPipe {
			receiver: std::sync::Arc::new(tokio::sync::Mutex::new(r)),
		},
	)
}
