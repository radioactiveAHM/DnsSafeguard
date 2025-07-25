<img src="./sample-256.png" width="256">

# DnsSafeguard

DnsSafeguard is a fast and secure DNS client written in Rust, designed to intercept DNS queries over a UDP socket and securely transmit them to a DNS server using DNS over HTTPS/TLS/QUIC (DoH/DoT/DoQ) protocols. By leveraging TLS client hello fragmentation and UDP Noise, it successfully bypasses the Great Firewall (GFW) censorship.

## Features

- **Secure Communication:** Utilizes Rustls for encrypted communication (TLS) with DNS servers.
- **UDP Socket:** Captures DNS queries on a UDP socket for efficient handling.
- **DoH Protocol:** Transmits DNS queries using the DoH protocol, supporting HTTP versions (HTTP/1.1, H2, H3) to ensure enhanced privacy.
- **DoT Protocol:** Transmits DNS queries using the DoT protocol with both blocking and non-blocking algorithms.
- **DoQ Protocol:** Transmits DNS queries using the DoQ protocol, providing highly secure and efficient communication, avoiding head-of-line blocking.
- **Rules:** Create rules for groups of domains and keywords to control DNS queries effectively.
- **Censorship Bypass:** Implements TLS client hello fragmentation with four methods to evade GFW TLS censorship.
- **Customizable UDP Noise:** Implements four types of UDP Noise to bypass QUIC blocking.

## Roadmap

- [x] IPv6 Support
- [x] HTTP/3 Support
- [x] HTTP/2 Support
- [x] HTTP/2 TLS Fragmentation
- [x] HTTP/1.1 Multi-Connection
- [x] DNS over TLS (DoT) with Blocking & Non-Blocking Support
- [x] UDP Noise Implementation
- [x] Advanced Rules Management
- [x] DNS over QUIC (DoQ) Support
- [x] Local HTTP/1.1 and HTTP/2 DoH Server (POST + GET)
- [x] Block DNS queries based on record type
- [x] Respond to the DNS query with a static IP(V4 and V6)
- [x] Owerwrite IPs from DNS responses
- [x] Interface/Adapter binding
- [x] POST Method (H2, H3)

## Building the Project

To build the project, execute the following command in the project directory:

```sh
cargo build --release
```

## How to Use

### Windows

1. **Download the Latest Release:**
    1. Visit the releases page and download the latest version of your DNS client.
    2. Extract the downloaded archive to a folder of your choice.
2. **Configure the `config.json` File:**
    1. Locate the `config.json` file in the extracted folder.
    2. Open it using a text editor.
    3. Modify the necessary settings based on the instructions in the “Configuration File” section.
3. **Run the DNS Client:**
    1. Execute the DNS client application (e.g., DnsSafeguard.exe).
    2. You should see log messages indicating that the client is attempting to establish a connection.
4. **Verify Connection Establishment:**
    - Keep an eye on the logs. When you see the message “Connection established,” it means the DNS client has successfully connected to the DNS server.
5. **Set Up Windows DNS:**
    1. Go to your Windows network settings.
    2. Configure the DNS server address to match the IP address specified in the `config.json` file for the `UDP Socket Addresses` section.

### Linux

Follow the same steps as Windows except for step 5: open the `/etc/resolv.conf` file and configure the DNS server address to match the IP address specified in the `config.json` file for the `UDP Socket Addresses` section. For example, if UDP Socket Addresses value is `127.0.0.1`, then the content in `/etc/resolv.conf` must be `nameserver 127.0.0.1`.

## DNS Server

[Go to DNS servers page](/DNS.md)

## Local DoH Server

[Go to local DoH server page](/DOHSERVER.md)

## Configuration File - `config.json`

The `config.json` file is a crucial part of the DnsSafeguard application. It contains the necessary settings to control the behavior of the DNS client.

### Protocols Info

- `h1` and `dot` are extremely cost-effective and operate on a single thread. All protocols establish a single connection, except for `h1_multi`, which supports multiple connections.
- `h3` and `doq` are built on the QUIC protocol and can be configured using the `Quic` section in the configuration file.

### Structure

The configuration file is structured in JSON format and includes the following settings:

- `Protocol`: Specifies the protocol used for DNS queries.
  - `h1`: Single HTTP/1.1 Connection.
  - `h1_multi`: Multiple HTTP/1.1 Connection.
  - `h2`: HTTP/2 Connection.
  - `h3`: HTTP/3 Connection.
  - `dot`: DOT Connection (DNS over TLS).
  - `dot_nonblocking`: DOT Non-Blocking Connection (DNS over TLS).
  - `doq`: DoQ Connection (DNS over QUIC).
- `Server Name`: The domain name of the DNS server.
- `Disable Domain SNI`: When enabled, the server name is not used as SNI, which can be a good alternative to the fragmenting method. Some public DNS servers, like Google, support this. Supported protocols include H1, H2, DoT, DoT_nonblocking, and H1_multi.
- `Disable Certificate Validation`: This option ignores certificate server name matching, enabling the use of domain fronting. For example, you can use `www.google.com` as the server name, which is not blocked by the Great Firewall (GFW). Many DNS servers, such as Google, Quad9, and NextDNS, support this option. However, Cloudflare does not, as it uses SNI guard. This is the best option for bypassing the GFW. **Disable Fragmenting**.
- `Socket Addresses`: The IP address and port for the DNS server connection.
- `Interface`: Name of the Interface/Adapter to bind to. Use `null` for default.
- `UDP Socket Addresses`: Local UDP address and port for DNS queries.
- `Custom Http Path`: Specify a custom HTTP path for HTTP-based protocols such as H1, H2, and H3. Use `null` for default which is the standard DoH path.
  - Examples: `/jsd3n5nb4/dns-query`, `/user/d618995a10e74acec7ed454ac6e39d6eb/dns-query`.
  - Warning: Custom path must end with `/dns-query`.
- `Http Method`: Values are `GET` and `POST`. GET is more compatible, it consumes more memory. POST, on the other hand, eliminates the need to encode DNS queries in base64url, resulting in lower memory usage. However, it requires two write system calls.
- `Fragmenting`: The fragmentation method to use during the TLS handshake. [Fragmenting page](/FRAG.md)
- `Noise`: UDP noise setting.
  - `ntype`: Noise type. Variants include `dns`, `str`, `lsd`, `tracker`, `stun`, `tftp` and `rand`.
  - `content`: Domain for `dns` ntype. Text for `str` ntype.
  - `packet_length`: Specifies the length of each noise packet in bytes for `rand` ntype.
  - `packets`: Indicates the total number of UDP noise packets to send for `rand` ntype.
  - `sleep`: Defines the sleep time (in milliseconds) after each UDP noise packet is sent.
- `IPv6`: Contains IPv6 specific settings, similar to the IPv4 configuration.
- `Quic`: Configuration for QUIC protocol.
  - `congestion_controller`: The congestion controller algorithm, options are `bbr`, `cubic` and `newreno`.
  - `keep_alive_interval`: The interval in seconds to keep the connection alive.
  - `datagram_receive_buffer_size`: Size of the receive buffer for datagrams. Use `null` for default.
  - `datagram_send_buffer_size`: Size of the send buffer for datagrams. Use `null` for default.
  - `connecting_timeout_sec`: Specifies the maximum connection timeout duration in seconds.
  - `packet_threshold`: Maximum reordering in packet number space before FACK style loss detection considers a packet lost. Should not be less than 3, per RFC5681.
  - `max_idle_timeout`: Maximum duration in seconds of inactivity to accept before timing out the connection. Use `null` for default.
- `connection`:
  - `h1_multi_connections`: Number of connections for the `h1 multi` protocol.
  - `reconnect_sleep`: Duration to sleep before reconnecting (in seconds).
  - `max_reconnect`: Maximum reconnect attempts before sleeping for a longer duration.
  - `max_reconnect_sleep`: Duration to sleep when the maximum reconnect attempts are reached.
- `tcp_socket_options`:
  - `send_buffer_size`: The size (in bytes) of the socket's send buffer. Use `null` for default.
  - `recv_buffer_size`: The size (in bytes) of the socket's receive buffer. Use `null` for default.
  - `nodelay`: Disables Nagle's algorithm when set to true. This reduces latency for small packets. Use `null` for default.
  - `keepalive`: keepalive enables TCP keepalive probes when set to true. Helps detect dead peers and maintain long-lived connections. Use `null` for default.
- `DoH Server`: Local DNS over HTTPS (HTTP/2) server for browsers.
  - `Listen Address`: The IP address and port of the local DoH server (e.g., `127.0.0.1:443`).
  - `ALPN`: Set up the HTTP version to serve. Supported variants are `h2` and `http/1.1`.
  - `Certificate`: Path to the certificate file (e.g., `/path/to/certificate.crt`).
  - `Key`: Path to the key file (e.g., `/path/to/key.key`).
  - `Cache Control`: cache control as response header.
  - `Log Errors`: Enable logging DoH sever errors.
- `Rules`: Block or bypass DNS queries containing specified domains or keywords. [Rules Page](/RULES.md).
- `Overwrite`: Overwrite IPs from DNS responses. [Overwrite Page](/OVERWRITE.md).

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
