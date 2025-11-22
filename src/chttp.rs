use crate::utils::Buffering;

#[inline(always)]
pub fn genrequrlh1<'a>(
	url: &'a mut Buffering,
	server_name: &[u8],
	query_bs4url: &[u8],
	path: &'static Option<String>,
) -> &'a [u8] {
	let main = b"GET /dns-query?dns=";
	let main_end = b" HTTP/1.1\r\nHost: ";
	let end = b"\r\nConnection: keep-alive\r\nAccept: application/dns-message\r\n\r\n";

	if let Some(cpath) = path {
		url.write(b"GET ")
			.write(cpath.as_bytes())
			.write(b"?dns=")
			.write(main_end)
			.write(server_name)
			.write(end)
			.get()
	} else {
		url.write(main)
			.write(query_bs4url)
			.write(main_end)
			.write(server_name)
			.write(end)
			.get()
	}
}
