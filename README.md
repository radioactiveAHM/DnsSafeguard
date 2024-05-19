# DnsSafeguard

**DnsSafeguard** is a secure DNS client built in Rust, designed to intercept DNS queries over a UDP socket and securely transmit them to a DNS server using the DNS over HTTPS (DOH) protocol. It also features TLS client hello fragmenting to circumvent Great Firewall (GFW) censorship.

## Features

* **Secure Communication**: Leverages Rustls for encrypted communication with DNS servers.
* **UDP Socket**: Captures DNS queries on a UDP socket.
* **DoH Protocol**: Sends DNS queries using the DoH protocol for enhanced privacy.
* **Censorship Bypass**: Utilizes TLS client hello fragmenting to evade GFW censorship.

## Roadmap

- [x] **IPv6 Support**: Current implementation.

## Building the Project

To build the project, execute the following command in the project directory: `cargo build --release`

## Config File

* `server_name`: Specifies the server name for TLS configuration.
* `socket_addrs`: Sets the DNS server IP and port.
* `udp_socket_addrs`: Configures the IP and port for the UDP socket listening to DNS queries.
* `fragment_method`: The fragmentation method to use during the TLS handshake has three valid values: `linear`, `random`, and `single`. Here’s what each method entails:
    - Linear Method: This method sends three TLS client hello packets in three separate TCP segments.
    - Random Method: In this approach, random TCP segments are used, each containing one TLS client hello packet.
    - Single Method: With the single method, a single TCP segment carries two TLS client hello packets.
* `ipv6`: Support for IPv6
