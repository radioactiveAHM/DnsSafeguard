use std::net::SocketAddr;

use crate::config::Noise;
use rand::Rng;
use tokio::time::sleep;

// Generate random standard dns record
pub mod dns {
    use rand::Rng;

    struct Query {
        asize: [u8; 1],
        a: Vec<u8>,
        bsize: [u8; 1],
        b: Vec<u8>,
        end: [u8; 1],
        rtype: [u8; 2],
        class: [u8; 2],
    }
    pub struct DnsRcord {
        id: [u8; 2],
        flags: [u8; 2],
        questions: [u8; 2],
        answerrrs: [u8; 2],
        authorityrrs: [u8; 2],
        additionalrrs: [u8; 2],
        queries: Query,
    }

    impl DnsRcord {
        fn into_buffer(&self) -> Vec<u8> {
            let a = [
                self.id,
                self.flags,
                self.questions,
                self.answerrrs,
                self.authorityrrs,
                self.additionalrrs,
            ]
            .concat();
            let b = [
                self.queries.asize.to_vec(),
                self.queries.a.to_vec(),
                self.queries.bsize.to_vec(),
                self.queries.b.to_vec(),
                self.queries.end.to_vec(),
                self.queries.rtype.to_vec(),
                self.queries.class.to_vec(),
            ]
            .concat();

            [a, b].concat()
        }

        pub fn with_domain(domain: &str) -> Vec<u8> {
            let mut random = [0u8; 1024];
            rand::thread_rng().fill(&mut random);

            let ab: Vec<&str> = domain.split(".").collect();
            let query = Query {
                asize: [ab[0].len() as u8],
                a: ab[0].into(),
                bsize: [ab[1].len() as u8],
                b: ab[1].into(),
                end: [0],
                rtype: [0, 1],
                class: [0, 1],
            };

            let record = DnsRcord {
                id: [random[0], random[1]],
                flags: [1, 0],
                questions: [0, 1],
                answerrrs: [0, 0],
                authorityrrs: [0, 0],
                additionalrrs: [0, 0],
                queries: query,
            };

            record.into_buffer()
        }
    }
}

pub async fn noiser(noise: Noise, target: SocketAddr, socket: &socket2::Socket){
    match noise.ntype.as_str() {
        "rand"=>{
            for _ in 0..noise.packets{
                // generate random packet
                let mut packet = [0u8;1024];
                rand::thread_rng().fill(&mut packet);
                // send packet
                if socket.send_to(&packet[..noise.packet_length], &target.into()).unwrap_or(0)==0{
                    println!("Noise failed");
                }
                sleep(std::time::Duration::from_millis(noise.sleep)).await;
            }
        },
        "dns"=>{
            if socket.send_to(&dns::DnsRcord::with_domain(&noise.content), &target.into()).unwrap_or(0)==0{
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        },
        "str"=>{
            if socket.send_to(noise.content.as_bytes(), &target.into()).unwrap_or(0)==0{
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        }
        _=>{
            panic!("Invalid noise type");
        }
    }
}