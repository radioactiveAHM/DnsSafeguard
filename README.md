# DnsSafeguard

**DnsSafeguard** is a secure DNS client built in Rust, designed to intercept DNS queries over a UDP socket and securely transmit them to a DNS server using the DNS over HTTPS (DOH) protocol. It also features TLS client hello fragmenting to circumvent Great Firewall (GFW) censorship.

Thank to [Rustls](https://github.com/rustls/rustls) developers for such a good TLS framework.

## Features

* **Secure Communication**: Leverages Rustls for encrypted communication with DNS servers.
* **UDP Socket**: Captures DNS queries on a UDP socket.
* **DoH Protocol**: Sends DNS queries using the DoH protocol for enhanced privacy.
* **Censorship Bypass**: Utilizes TLS client hello fragmenting to evade GFW censorship.

## Roadmap

* [x] **IPv6 Support**
* [x] **HTTP/3**
* [x] **HTTP/2**
* [x] **HTTP/2 TLS Fragmenting**
* [ ] **ECH**
* [ ] **HTTP/1.1 Multi-Connection**
* [ ] **Better Commenting 😅**

## Building the Project

To build the project, execute the following command in the project directory: `cargo build --release`

## Configuration File - `config.json`

The `config.json` file is a crucial part of the DnsSafeguard application. It contains the necessary settings to control the behavior of the DNS client.

### Structure

The configuration file is structured in JSON format and includes the following settings:

* `HTTP Version`: Specifies the HTTP protocol version used for DNS queries (HTTP version 3 does not support Fragmenting).
* `Server Name`: The domain name of the DNS server.
* `Socket Addresses`: The IP address and port for the DNS server connection.
* `UDP Socket Addresses`: Local UDP address and port for DNS queries.
* `Fragmenting`: The fragmentation method to use during the TLS handshake has three valid values: `linear`, `random`, and `single`. Here’s what each method entails:
  * Linear Method: This method sends three TLS client hello packets in three separate TCP segments.
  * Random Method: In this approach, random TCP segments are used, each containing one TLS client hello packet.
  * Single Method: With the single method, a single TCP segment carries two TLS client hello packets.
* `IPv6`: Contains IPv6 specific settings, similar to the IPv4 configuration.
* `Quic`: Configuration for QUIC protocol.
  * `congestion_controller`: The congestion controller algorithm, default is `bbr`.
  * `keep_alive_interval`: The interval in seconds to keep the connection alive, default is `5`.
  * `datagram_receive_buffer_size`: Size of the receive buffer for datagrams, default is `16777216`.
  * `datagram_send_buffer_size`: Size of the send buffer for datagrams, default is `8388608`.

## Notes

> [!WARNING]
> Using self-modified verion of tokio-rustls.
> Only TLS 1.3 supported for better performance.

## TLS Features

* Brotli certificate compression
* Tls client hello Fragmenting

## License

This project is licensed under the Apache-2.0 License - see the LICENSE file for details.
