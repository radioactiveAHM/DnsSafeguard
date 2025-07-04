use std::net::SocketAddr;

use crate::config::{Noise, NoiseType};
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
        fn into_buffer(self) -> Vec<u8> {
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
            rand::rng().fill(&mut random);

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

pub mod lsd {
    use std::net::SocketAddr;

    use rand::{
        Rng,
        distr::{Alphanumeric, SampleString},
        rng,
    };

    pub struct Lsd<'a> {
        // [13u8, 10] after each part
        header: &'a str,
        host: String,
        port: String,
        infohash: String,
        cookie: String, // [13u8, 10, 13u8, 10, 13u8, 10]
    }

    impl Lsd<'_> {
        pub fn new(target: SocketAddr) -> Self {
            let mut rng = rng();
            Lsd {
                header: "BT-SEARCH * HTTP/1.1",
                host: format!("Host: {target}"),
                port: format!("Port: {}", rng.random::<u16>()),
                infohash: format!("Infohash: {}", Alphanumeric.sample_string(&mut rng, 40)),
                cookie: format!("Cookie: {}", Alphanumeric.sample_string(&mut rng, 8)),
            }
        }

        pub fn into_buffer(self) -> Vec<u8> {
            // I know &[13, 10] is same is \r\n but i liked this way :)
            [
                self.header.as_bytes(),
                &[13, 10],
                self.host.as_bytes(),
                &[13, 10],
                self.port.as_bytes(),
                &[13, 10],
                self.infohash.as_bytes(),
                &[13, 10],
                self.cookie.as_bytes(),
                &[13, 10, 13, 10, 13, 10],
            ]
            .concat()
        }
    }
}

struct Tracker {
    protocol: [u8; 8],
    action: [u8; 4],
    tid: [u8; 4],
}
impl Tracker {
    fn new() -> Self {
        Self {
            protocol: [0, 0, 4, 23, 39, 16, 25, 128],
            action: [0, 0, 0, 0],
            tid: rand::random(),
        }
    }
    fn bytes(self) -> Vec<u8> {
        [
            self.protocol.as_slice(),
            self.action.as_slice(),
            self.tid.as_slice(),
        ]
        .concat()
    }
}

fn stun() -> [u8; 20] {
    let mut message = [
        0, 1, 0, 0, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    rand::rng().fill(&mut message[8..]);
    message
}

pub async fn noiser(noise: &Noise, target: SocketAddr, socket: &socket2::Socket) {
    if noise.continues {
        if let Ok(s) = socket.try_clone() {
            let noise = noise.clone();
            tokio::spawn(async move {
                continues_noise(noise, target, s).await;
            });
        } else {
            println!("continues unavailable");
        }
    }

    match noise.ntype {
        NoiseType::rand => {
            rand_noiser(noise, target, socket).await;
        }
        NoiseType::dns => {
            if socket
                .send_to(&dns::DnsRcord::with_domain(&noise.content), &target.into())
                .is_err()
            {
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        }
        NoiseType::str => {
            if socket
                .send_to(noise.content.as_bytes(), &target.into())
                .is_err()
            {
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        }
        NoiseType::lsd => {
            if socket
                .send_to(&lsd::Lsd::new(target).into_buffer(), &target.into())
                .is_err()
            {
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        }
        NoiseType::tracker => {
            if socket
                .send_to(&Tracker::new().bytes(), &target.into())
                .is_err()
            {
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        }
        NoiseType::stun => {
            if socket.send_to(&stun(), &target.into()).is_err() {
                println!("Noise failed");
            }
            sleep(std::time::Duration::from_millis(noise.sleep)).await;
        }
    }
    println!("Noise sent");
}

async fn continues_noise(noise: Noise, target: SocketAddr, socket: socket2::Socket) {
    loop {
        match noise.ntype {
            NoiseType::rand => {
                rand_noiser(&noise, target, &socket).await;
            }
            NoiseType::dns => {
                if socket
                    .send_to(&dns::DnsRcord::with_domain(&noise.content), &target.into())
                    .is_err()
                {
                    println!("Noise failed");
                }
                sleep(std::time::Duration::from_millis(noise.sleep)).await;
            }
            NoiseType::str => {
                if socket
                    .send_to(noise.content.as_bytes(), &target.into())
                    .is_err()
                {
                    println!("Noise failed");
                }
                sleep(std::time::Duration::from_millis(noise.sleep)).await;
            }
            NoiseType::lsd => {
                if socket
                    .send_to(&lsd::Lsd::new(target).into_buffer(), &target.into())
                    .is_err()
                {
                    println!("Noise failed");
                }
                sleep(std::time::Duration::from_millis(noise.sleep)).await;
            }
            NoiseType::tracker => {
                if socket
                    .send_to(&Tracker::new().bytes(), &target.into())
                    .is_err()
                {
                    println!("Noise failed");
                }
                sleep(std::time::Duration::from_millis(noise.sleep)).await;
            }
            NoiseType::stun => {
                if socket.send_to(&stun(), &target.into()).is_err() {
                    println!("Noise failed");
                }
                sleep(std::time::Duration::from_millis(noise.sleep)).await;
            }
        }
    }
}

#[inline(never)]
async fn rand_noiser(noise: &Noise, target: SocketAddr, socket: &socket2::Socket) {
    for _ in 0..noise.packets {
        // generate random packet
        let mut packet = [0u8; 1024];
        rand::rng().fill(&mut packet);
        // send packet
        if socket
            .send_to(&packet[..noise.packet_length], &target.into())
            .unwrap_or(0)
            == 0
        {
            println!("Noise failed");
        }
        sleep(std::time::Duration::from_millis(noise.sleep)).await;
    }
}
