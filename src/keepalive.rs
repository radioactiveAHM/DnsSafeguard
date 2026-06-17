pub async fn pipe_recv_timeout_with<Fu>(
	rpipe: &crate::pipe::ReceiverPipe,
	dur: Option<u64>,
	f: Fu,
) -> tokio::io::Result<Option<crate::pipe::Message>>
where
	Fu: Future<Output = tokio::io::Result<()>>,
{
	let poll_recv = rpipe.recv_message();
	if let Some(dur) = dur {
		match tokio::time::timeout(std::time::Duration::from_secs(dur), poll_recv).await {
			Ok(message) => Ok(Some(message)),
			Err(_) => {
				f.await?;
				Ok(None)
			}
		}
	} else {
		Ok(Some(poll_recv.await))
	}
}
