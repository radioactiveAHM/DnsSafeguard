use core::str;
use std::sync::Arc;

pub fn genrequrl<'a>(
    url: &'a mut [u8],
    server_name: &[u8],
    query_bs4url: &[u8],
    path: Option<Arc<str>>,
) -> &'a str {
    if let Some(cpath) = path {
        let scheme = b"https://";
        let dnsprop = b"?dns=";

        url[..scheme.len()].copy_from_slice(scheme);
        url[scheme.len()..server_name.len() + scheme.len()].copy_from_slice(server_name);
        url[scheme.len() + server_name.len()..cpath.len() + scheme.len() + server_name.len()]
            .copy_from_slice(cpath.as_bytes());
        url[cpath.len() + scheme.len() + server_name.len()
            ..dnsprop.len() + cpath.len() + scheme.len() + server_name.len()]
            .copy_from_slice(dnsprop);
        url[dnsprop.len() + cpath.len() + scheme.len() + server_name.len()
            ..query_bs4url.len() + dnsprop.len() + cpath.len() + scheme.len() + server_name.len()]
            .copy_from_slice(query_bs4url);
        str::from_utf8(
            &url[..query_bs4url.len()
                + dnsprop.len()
                + cpath.len()
                + scheme.len()
                + server_name.len()],
        )
        .unwrap()
    } else {
        let scheme = b"https://";
        let path = b"/dns-query?dns=";

        url[..scheme.len()].copy_from_slice(scheme);
        url[scheme.len()..server_name.len() + scheme.len()].copy_from_slice(server_name);
        url[scheme.len() + server_name.len()..path.len() + scheme.len() + server_name.len()]
            .copy_from_slice(path);
        url[scheme.len() + server_name.len() + path.len()
            ..query_bs4url.len() + scheme.len() + server_name.len() + path.len()]
            .copy_from_slice(query_bs4url);
        str::from_utf8(&url[..scheme.len() + server_name.len() + path.len() + query_bs4url.len()])
            .unwrap()
    }
}

pub fn genrequrlh1<'a>(
    url: &'a mut [u8],
    server_name: &[u8],
    query_bs4url: &[u8],
    path: &Option<&str>,
) -> &'a [u8] {
    let main = b"GET /dns-query?dns=";
    let main_end = b" HTTP/1.1\r\nHost: ";
    let end = b"\r\nConnection: keep-alive\r\nAccept: application/dns-message\r\n\r\n";

    if let Some(cpath) = path {
        let method = b"GET ";
        let dnsprop = b"?dns=";

        url[..method.len()].copy_from_slice(method);
        url[method.len()..cpath.len() + method.len()].copy_from_slice(cpath.as_bytes());
        url[cpath.len() + method.len()..dnsprop.len() + cpath.len() + method.len()]
            .copy_from_slice(dnsprop);
        url[dnsprop.len() + cpath.len() + method.len()
            ..query_bs4url.len() + dnsprop.len() + cpath.len() + method.len()]
            .copy_from_slice(query_bs4url);
        url[query_bs4url.len() + dnsprop.len() + cpath.len() + method.len()
            ..main_end.len() + query_bs4url.len() + dnsprop.len() + cpath.len() + method.len()]
            .copy_from_slice(main_end);
        url[main_end.len() + query_bs4url.len() + dnsprop.len() + cpath.len() + method.len()
            ..server_name.len()
                + main_end.len()
                + query_bs4url.len()
                + dnsprop.len()
                + cpath.len()
                + method.len()]
            .copy_from_slice(server_name);
        url[server_name.len()
            + main_end.len()
            + query_bs4url.len()
            + dnsprop.len()
            + cpath.len()
            + method.len()
            ..end.len()
                + server_name.len()
                + main_end.len()
                + query_bs4url.len()
                + dnsprop.len()
                + cpath.len()
                + method.len()]
            .copy_from_slice(end);

        &url[..end.len()
            + server_name.len()
            + main_end.len()
            + query_bs4url.len()
            + dnsprop.len()
            + cpath.len()
            + method.len()]
    } else {
        url[..main.len()].copy_from_slice(main);
        url[main.len()..query_bs4url.len() + main.len()].copy_from_slice(query_bs4url);
        url[query_bs4url.len() + main.len()..main_end.len() + query_bs4url.len() + main.len()]
            .copy_from_slice(main_end);
        url[main_end.len() + query_bs4url.len() + main.len()
            ..server_name.len() + main_end.len() + query_bs4url.len() + main.len()]
            .copy_from_slice(server_name);
        url[server_name.len() + main_end.len() + query_bs4url.len() + main.len()
            ..end.len() + server_name.len() + main_end.len() + query_bs4url.len() + main.len()]
            .copy_from_slice(end);

        &url[..end.len() + server_name.len() + main_end.len() + query_bs4url.len() + main.len()]
    }
}
