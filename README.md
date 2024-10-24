<img src="./sample-256.png" width="256">

# DnsSafeguard

DnsSafeguard is a fast and secure DNS client written in Rust, designed to intercept DNS queries over a UDP socket and securely transmit them to a DNS server using DNS over HTTPS/TLS/QUIC (DoH/DoT/DoQ) protocols. By leveraging TLS client hello fragmentation and UDP Noise, it successfully bypasses the Great Firewall (GFW) censorship.

## Features

* **Secure Communication:** Utilizes Rustls for encrypted communication (TLS) with DNS servers.
* **UDP Socket:** Captures DNS queries on a UDP socket for efficient handling.
* **DoH Protocol:** Transmits DNS queries using the DoH protocol, supporting HTTP versions (HTTP/1.1, H2, H3) to ensure enhanced privacy.
* **DoT Protocol:** Transmits DNS queries using the DoT protocol with both blocking and non-blocking algorithms.
* **DoQ Protocol:**  Transmits DNS queries using the DoQ protocol, providing highly secure and efficient communication, avoiding head-of-line blocking.
* **Rules:** Create rules for groups of domains and keywords to control DNS queries effectively.
* **Censorship Bypass:** Implements TLS client hello fragmentation with four methods to evade GFW TLS censorship.
* **Customizable UDP Noise** Implements four types of UDP Noise to bypass QUIC blocking.

## Roadmap

* [x] IPv6 Support
* [x] HTTP/3 Support
* [x] HTTP/2 Support
* [x] HTTP/2 TLS Fragmentation
* [x] HTTP/1.1 Multi-Connection
* [x] DNS over TLS (DoT) with Blocking & Non-Blocking Support
* [x] UDP Noise Implementation
* [x] Advanced Rules Management
* [x] DNS over QUIC (DoQ) Support

## Building the Project

To build the project, execute the following command in the project directory: `cargo build --release`

## How to use

* **Windows**
  1. Download the Latest Release:
      1. Visit the releases page and download the latest version of your DNS client.
      2. Extract the downloaded archive to a folder of your choice.
  2. Configure the `config.json` File:
      1. Locate the `config.json` file in the extracted folder.
      2. Open it using a text editor.
      3. Modify the necessary settings based on the instructions in the “Configuration File” section.
  3. Run the DNS Client:
      1. Execute the DNS client application (e.g., DnsSafeguard.exe).
      2. You should see log messages indicating that the client is attempting to establish a connection.
  4. Verify Connection Establishment:
      * Keep an eye on the logs. When you see the message “Connection established,” it means the DNS client has successfully connected to the DNS server.
  5. Set Up Windows DNS:
      1. Go to your Windows network settings.
      2. Configure the DNS server address to match the IP address specified in the config.json file for the `UDP Socket Addresses` section.

* **Linux**
  * Exact same steps as Windows except for step 5: open the `/etc/resolv.conf` file and configure the DNS server address to match the IP address specified in the `config.json` file for the `UDP Socket Addresses` section. For example, if UDP Socket Addresses value is `127.0.0.1`, then the content in `/etc/resolv.conf` must be `nameserver 127.0.0.1`.

## DNS server

[Go to dns servers page](/DNS.md)

## Configuration File - `config.json`

The `config.json` file is a crucial part of the DnsSafeguard application. It contains the necessary settings to control the behavior of the DNS client.

### Protocols info

* `h1` and `dot` are extremely cost-effective and operate on a single thread. All protocols establish a single connection, except for `h1 multi`, which supports multiple connections.
* `h3` and `doq` are built on the QUIC protocol and can be configured using the `Quic` section in the configuration file.

### Structure

The configuration file is structured in JSON format and includes the following settings:

* `Protocol`: Specifies the protocol used for DNS queries.
  * `h1`: Single HTTP/1.1 Connection.
  * `h1 multi`: Multiple HTTP/1.1 Connection.
  * `h2`: HTTP/2 Connection.
  * `h3`: HTTP/3 Connection (does not support fragmenting).
  * `dot`: DOT Connection (DNS over TLS).
  * `dot nonblocking`: DOT Non-Blocking Connection (DNS over TLS).
  * `doq`: DoQ Connection (DNS over QUIC).
* `Server Name`: The domain name of the DNS server.
* `Socket Addresses`: The IP address and port for the DNS server connection.
* `UDP Socket Addresses`: Local UDP address and port for DNS queries.
* `Fragmenting`: The fragmentation method to use during the TLS handshake has three valid values: `linear`, `random`, `single` and `jump`.
* `Noise`: UDP noise setting.
  * `ntype`: Noise type. Variants include `dns`, `str`, `lsd`, and `rand`.
  * `content`: Domain for `dns` ntype. Text for `str` ntype.
  * `packet_length`: Specifies the length of each noise packet in bytes for `rand` ntype.
  * `packets`: Indicates the total number of UDP noise packets to send for `rand` ntype.
  * `sleep`: Defines the sleep time (in milliseconds) after each UDP noise packet is sent.
  * `continues`: Enables continuous noise sending.
* `IPv6`: Contains IPv6 specific settings, similar to the IPv4 configuration.
* `Quic`: Configuration for QUIC protocol.
  * `congestion_controller`: The congestion controller algorithm, options are `bbr`, `cubic` and `newreno`.
  * `keep_alive_interval`: The interval in seconds to keep the connection alive.
  * `datagram_receive_buffer_size`: Size of the receive buffer for datagrams.
  * `datagram_send_buffer_size`: Size of the send buffer for datagrams.
  * `connecting_timeout_sec`: Specifies the maximum connection timeout duration in seconds.
* `Connection`: Connection settings.
  * `h1_multi_connections`: Number of connections for the `h1 multi` protocol.
  * `reconnect_sleep`: Duration to sleep before reconnecting (in seconds).
  * `max_reconnect`: Maximum reconnect attempts before sleeping for a longer duration.
  * `max_reconnect_sleep`: Duration to sleep when the maximum reconnect attempts are reached.
* `rules`: Block or bypass DNS queries containing specified domains or keywords.
  * `enable`: Enable or disable rules.
  * `rule`: List of defined rules.
    * `options`: List of domains or keywords.
    * `target`: Can be `block` or a DNS server providing plaintext UDP protocol (e.g., 1.1.1.1:53).

## Notes

> [!WARNING]
> Only TLS 1.3 supported for better performance.

## License

This project is licensed under the Apache *2.0 License - see the LICENSE file for details.
