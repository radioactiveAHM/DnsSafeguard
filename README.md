# DnsSafeguard

This project is a secure DNS client built in Rust that captures DNS queries over a UDP socket and sends them to a DNS server using the DNS over HTTPS (DOH) protocol. Additionally, it employs TLS client hello fragmenting to bypass Great Firewall (GFW) censorship.

## Features

* Secure Communication: Utilizes Rustls for secure communication with DNS servers.
* UDP Socket: Listens for DNS queries on a UDP socket.
* DoH Protocol: Transmits DNS queries to a DNS server using the DoH protocol.
* Censorship Bypass: Implements TLS client hello fragmenting to evade GFW censorship.

## Roadmap

- [ ] Dual Stack
- [ ] Configuration options for blocking dns query by specific key in domain name
- [ ] DNS over TLS (Port 853)

## Build

To build run `cargo build --release` in project directory

## Config File

* server_name: Required for TLS config.
* socket_addrs: DNS server IP and port.
* udp_socket_addrs: Configure the IP address and port for listening to DNS queries on a UDP socket. DNS servers typically listen on port 53.
