pub async fn race_connect<F, Fu, T>(remote_addrs: &[std::net::SocketAddr], f: F) -> Option<T>
where
	F: Fn(std::net::SocketAddr) -> Fu,
	Fu: Future<Output = Option<T>> + Send + 'static,
	T: Send + 'static,
{
	if remote_addrs.len() > 1 {
		let mut set = tokio::task::JoinSet::new();

		for &addr in remote_addrs {
			let fu = f(addr);
			set.spawn(async move { (fu.await, addr) });
		}

		while let Some(Ok((result, addr))) = set.join_next().await {
			if result.is_some() {
				log::info!("{addr} selected");
				set.abort_all();
				return result;
			}
		}
		None
	} else {
		f(remote_addrs[0]).await
	}
}
