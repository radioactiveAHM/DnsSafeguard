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
            Ok(stream)=>{
                return stream;
            }
            Err(e)=>{
                if retry == 5{
                    println!("Max retry reached. Sleeping for 1Min");
                    sleep(std::time::Duration::from_secs(60)).await;
                    retry=0;
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