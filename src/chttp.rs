use core::str;
use std::{str::Utf8Error, sync::Arc};
use crate::utils::Buffering;

pub fn genrequrl<'a>(
    url: &'a mut Buffering,
    server_name: &[u8],
    query_bs4url: &[u8],
    path: Option<Arc<str>>,
) -> Result<&'a str, Utf8Error> {
    if let Some(cpath) = path {
        url.write(b"https://")
        .write(server_name)
        .write(cpath.as_bytes())
        .write(b"?dns=")
        .write(query_bs4url)
        .str()
    } else {
        url.write(b"https://")
        .write(server_name)
        .write(b"/dns-query?dns=")
        .write(query_bs4url)
        .str()
    }
}

pub fn genrequrlh1<'a>(
    url: &'a mut Buffering,
    server_name: &[u8],
    query_bs4url: &[u8],
    path: &Option<&str>,
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
