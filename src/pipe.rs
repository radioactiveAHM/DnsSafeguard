use bytes::Bytes;

pub enum Message {
	Udp(std::sync::Arc<tokio::net::UdpSocket>, std::net::SocketAddr, Vec<u8>),
	Doh(crossfire::oneshot::TxOneshot<Bytes>, Bytes),
}

impl Message {
	pub async fn send_response(self, buf: Bytes) {
		match self {
			Self::Udp(udp, addr, _) => {
				let _ = udp.send_to(&buf, addr).await;
			}
			Self::Doh(oc, _) => oc.send(buf),
		}
	}

	pub async fn send_response_slice(self, buf: &[u8]) {
		match self {
			Self::Udp(udp, addr, _) => {
				let _ = udp.send_to(buf, addr).await;
			}
			Self::Doh(oc, _) => oc.send(Bytes::copy_from_slice(buf)),
		}
	}

	pub fn message_slice(&self) -> &[u8] {
		match self {
			Self::Udp(_, _, b) => b,
			Self::Doh(_, b) => b,
		}
	}
}

#[derive(Clone)]
pub struct ReceiverPipe {
	receiver: crossfire::MAsyncRx<crossfire::mpmc::Array<Message>>,
}

impl ReceiverPipe {
	pub async fn recv_message(&self) -> Message {
		self.receiver.recv().await.unwrap()
	}
}

// ----------------------

#[derive(Clone)]
pub struct SendPipe {
	sender: crossfire::MAsyncTx<crossfire::mpmc::Array<Message>>,
}

impl SendPipe {
	pub async fn pipe_udp_message(self, udp: std::sync::Arc<tokio::net::UdpSocket>) {
		// EDNS(0) = 65535
		let mut buf = vec![0; 1024 * 64];
		loop {
			if let Ok((size, addr)) = udp.recv_from(&mut buf).await {
				if size < 17 {
					log::info!("Invalid query: Expected >= 17 bytes, received {size}. Dropping packet from {addr}.");
					continue;
				}
				self.sender
					.send(Message::Udp(std::sync::Arc::clone(&udp), addr, buf[..size].to_vec()))
					.await
					.unwrap();
			}
		}
	}

	pub async fn send_doh_message(&self, buf: Bytes) -> crossfire::oneshot::RxOneshot<Bytes> {
		let (sender, recver) = crossfire::oneshot::oneshot::<Bytes>();
		self.sender.send(Message::Doh(sender, buf)).await.unwrap();
		recver
	}
}

// ----------------------

pub fn new_message_pipe(cap: usize) -> (SendPipe, ReceiverPipe) {
	let (s, r) = crossfire::mpmc::bounded_async::<Message>(cap);
	(SendPipe { sender: s }, ReceiverPipe { receiver: r })
}
