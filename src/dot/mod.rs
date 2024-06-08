use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{config, multi::tls_conn_gen, tls};

pub async fn dot(
    server_name: String,
    socket_addrs: &str,
    udp_socket_addrs: &str,
    fragmenting: &config::Fragmenting,
) {
    let ctls = tls::tlsconf(vec![b"dot".to_vec()]);
    let mut retry = 0u8;
    loop {
        if retry == 5 {
            break;
        }
        let tls_conn = tls_conn_gen(
            server_name.clone(),
            socket_addrs.to_string(),
            fragmenting.clone(),
            ctls.clone(),
        )
        .await;
        if tls_conn.is_err() {
            // If tls handshake failed retry
            println!("TLS handshake failed");
            retry += 1;
            continue;
        }
        println!("TLS Connection Established");
        retry = 0;

        // Tls Client
        let mut conn = tls_conn.unwrap();
        // UDP Server to recv dns query
        let udp = tokio::net::UdpSocket::bind(udp_socket_addrs).await.unwrap();

        loop {
            // Recv dns query
            let mut query = [0; 768];
            if let Ok((query_size, addr)) = udp.recv_from(&mut query).await {
                // DNS query with two u8 size which is required by DOT
                // Size of dns Query as two u8
                let dot_size = convert_u16_to_two_u8s_be(query_size as u16);
                let dot_query = [&[dot_size[0], dot_size[1]], &query[..query_size]].concat();

                // Send DOT query
                if conn.write(&dot_query).await.is_err() {
                    // Connection is closed
                    println!("connection closed by peer");
                    break;
                }

                // Recv DOT query
                let mut resp_dot_query = [0; 768];
                if let Ok(resp_dot_query_size) = conn.read(&mut resp_dot_query).await {
                    udp.send_to(&resp_dot_query[2..(resp_dot_query_size - 2)], addr)
                        .await
                        .unwrap_or(0);
                } else {
                    // Connection is closed
                    println!("connection closed by peer");
                    break;
                }
            }
        }
    }
}

fn convert_u16_to_two_u8s_be(integer: u16) -> [u8; 2] {
    [(integer >> 8) as u8, integer as u8]
}
