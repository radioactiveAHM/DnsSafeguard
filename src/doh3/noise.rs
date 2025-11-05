use std::net::SocketAddr;

use crate::config::{Noise, NoiseType};
use rand::{
    Rng,
    distr::{Alphanumeric, SampleString},
    rng,
};
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

struct Lsd<'a> {
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

fn tftp() -> Vec<u8> {
    // TODO: Add write mode
    let mut packet: Vec<u8> = vec![0, 1];

    let mut rng = rng();
    let filename_len = rng.random_range(1..128);
    packet.extend_from_slice(
        Alphanumeric
            .sample_string(&mut rng, filename_len)
            .as_bytes(),
    );

    //                          |---".bin"---|
    packet.extend_from_slice(&[46, 98, 105, 110, 0, 111, 99, 116, 101, 116, 0]);

    packet
}

fn ntp() -> [u8; 48] {
    let mut rng = rand::rng();
    let mut packet: [u8; 48] = [
        219, 0, 17, 233, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 236, 77, 18, 206, 29, 109, 124, 219,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 236, 77, 36, 9, 81, 101, 92, 123,
    ];

    rng.fill(&mut packet[2..12]);
    rng.fill(&mut packet[16..24]);
    rng.fill(&mut packet[40..]);
    packet
}

fn syslog() -> Vec<u8> {
    let mut packet = Vec::with_capacity(256);
    packet.extend_from_slice(&[60, 49, 54, 53, 62, 49, 32]);
    packet.extend_from_slice(&[0; 24]);

    let mut rng = rand::rng();

    let host = crate::CONFIG.server_name.as_str();
    let pid: u8 = rng.random();
    let mid: u8 = rng.random();
    let mlen = rng.random_range(10..256);
    packet.extend_from_slice(
        format!(
            " {host} syslog {pid} ID{mid} - {}",
            Alphanumeric.sample_string(&mut rng, mlen)
        )
        .as_bytes(),
    );

    packet
}

#[inline(never)]
async fn rand_noiser(
    noise: &Noise,
    target: SocketAddr,
    socket: &socket2::Socket,
) -> tokio::io::Result<usize> {
    let mut packet = [0u8; 1500];
    let psize_range = crate::utils::parse_range(&noise.packet_length)
        .expect("Failed to parse packet length range");
    let mut sent_bytes = 0;
    for _ in 0..noise.packets {
        rand::rng().fill(&mut packet);
        sent_bytes += socket.send_to(
            &packet[..rand::rng().random_range(psize_range.clone())],
            &target.into(),
        )?;
        sleep(std::time::Duration::from_millis(noise.sleep)).await;
    }
    Ok(sent_bytes)
}

pub async fn noiser(noise: &Noise, target: SocketAddr, socket: &socket2::Socket) {
    if let Ok(sent_bytes) = match noise.ntype {
        NoiseType::rand => rand_noiser(noise, target, socket).await,
        NoiseType::dns => {
            socket.send_to(&dns::DnsRcord::with_domain(&noise.content), &target.into())
        }
        NoiseType::str => socket.send_to(noise.content.as_bytes(), &target.into()),
        NoiseType::lsd => socket.send_to(&Lsd::new(target).into_buffer(), &target.into()),
        NoiseType::tracker => socket.send_to(&Tracker::new().bytes(), &target.into()),
        NoiseType::stun => socket.send_to(&stun(), &target.into()),
        NoiseType::tftp => socket.send_to(&tftp(), &target.into()),
        NoiseType::ntp => socket.send_to(&ntp(), &target.into()),
        NoiseType::syslog => socket.send_to(&syslog(), &target.into()),
    } {
        log::info!("{sent_bytes} bytes sent as noise");
        sleep(std::time::Duration::from_millis(noise.sleep)).await;
    } else {
        log::warn!("Noise failed");
    }
}
