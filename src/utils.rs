use core::str;

use tokio::{net::TcpStream, time::sleep};

#[allow(unused)]
pub fn convert_u16_to_two_u8s_be(integer: u16) -> [u8; 2] {
    [(integer >> 8) as u8, integer as u8]
}
#[allow(unused)]
pub fn convert_two_u8s_to_u16_be(bytes: [u8; 2]) -> u16 {
    ((bytes[0] as u16) << 8) | bytes[1] as u16
}

pub async fn tcp_connect_handle(socket_addrs: &str) -> TcpStream {
    let mut retry = 0u8;
    loop {
        match tokio::net::TcpStream::connect(socket_addrs).await {
            Ok(stream) => {
                return stream;
            }
            Err(e) => {
                if retry == 5 {
                    println!("Max retry reached. Sleeping for 1Min");
                    sleep(std::time::Duration::from_secs(60)).await;
                    retry = 0;
                    continue;
                }
                println!("{}", e);
                retry += 1;
                sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}

pub fn genrequrl<'a>(url: &'a mut [u8],server_name: &[u8], query_bs4url: &[u8])->&'a str{
    let scheme = b"https://";
    let path = b"/dns-query?dns=";

    url[..scheme.len()].copy_from_slice(scheme);
    url[scheme.len()..server_name.len()+scheme.len()].copy_from_slice(server_name);
    url[scheme.len()+server_name.len()..path.len()+scheme.len()+server_name.len()].copy_from_slice(path);
    url[scheme.len()+server_name.len()+path.len()..query_bs4url.len()+scheme.len()+server_name.len()+path.len()].copy_from_slice(query_bs4url);
    str::from_utf8(&url[..scheme.len()+server_name.len()+path.len()+query_bs4url.len()]).unwrap()
}

pub fn genrequrlh1<'a>(url: &'a mut [u8],server_name: &[u8], query_bs4url: &[u8])->&'a [u8]{
    let main = b"GET /dns-query?dns=";
    let main_end = b" HTTP/1.1\r\nHost: ";
    let heads = b"\r\nConnection: keep-alive\r\nAccept: application/dns-message\r\n\r\n";

    url[..main.len()].copy_from_slice(main);
    url[main.len()..query_bs4url.len()+main.len()].copy_from_slice(query_bs4url);
    url[query_bs4url.len()+main.len()..main_end.len()+query_bs4url.len()+main.len()].copy_from_slice(main_end);
    url[main_end.len()+query_bs4url.len()+main.len()..server_name.len()+main_end.len()+query_bs4url.len()+main.len()].copy_from_slice(server_name);
    url[server_name.len()+main_end.len()+query_bs4url.len()+main.len()..heads.len()+server_name.len()+main_end.len()+query_bs4url.len()+main.len()].copy_from_slice(heads);

    &url[..heads.len()+server_name.len()+main_end.len()+query_bs4url.len()+main.len()]
}