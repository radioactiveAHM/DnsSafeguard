# DnsSafeguard

![DnsSafeguard](./sample-256.png)

DnsSafeguard is a fast and secure DNS client written in Rust, designed to intercept DNS queries over a UDP socket and Dns over HTTPS (DoH) to securely transmit them to a DNS server using DNS over HTTPS/TLS/QUIC (DoH/DoT/DoQ) protocols. By leveraging TLS client hello fragmentation and UDP Noise, it successfully bypasses the Great Firewall (GFW) censorship.

## Struct

![Graph](./DnsSafeguard%20graph.webp)

## Safety

This crate uses `#![forbid(unsafe_code)]` to ensure everything is implemented in 100% safe Rust.

## Features

- **Secure Communication:** Utilizes Rustls for encrypted communication (TLS) with DNS servers.
- **UDP Socket:** Captures DNS queries on a UDP socket for efficient handling.
- **DoH Protocol:** Transmits DNS queries using the DoH protocol, supporting HTTP versions (HTTP/1.1, H2, H3) to ensure enhanced privacy.
- **DoT Protocol:** Transmits DNS queries using the DoT protocol.
- **DoQ Protocol:** Transmits DNS queries using the DoQ protocol, providing highly secure and efficient communication, avoiding head-of-line blocking.
- **Rules:** Create rules for groups of domains and keywords to control DNS queries effectively.
- **Overwrite:** Overwrite IPs from DNS responses.
- **Censorship Bypass:** Implements TLS client hello fragmentation with four methods to evade GFW TLS censorship.
- **Customizable UDP Noise:** Implements 7 dynamic types of UDP Noise to bypass QUIC blocking.

## Roadmap

- [x] IPv6 Support
- [x] HTTP/3 Support
- [x] HTTP/2 Support
- [x] HTTP/2 TLS Fragmentation
- [x] HTTP/1.1 Multi-Connection
- [x] DNS over TLS (DoT)
- [x] UDP Noise Implementation
- [x] Advanced Rules Management
- [x] DNS over QUIC (DoQ) Support
- [x] Local HTTP/1.1 and HTTP/2 DoH Server (POST + GET)
- [x] Block DNS queries based on record type
- [x] Respond to the DNS query with a static IP(V4 and V6)
- [x] Owerwrite IPs from DNS responses
- [x] Interface/Adapter binding
- [x] POST Method (H2, H3)
- [x] Logging

## Building the Project

This project supports two cryptographic backends: **aws-lc-rs** (default) and **ring**. Choose the appropriate build command based on your desired backend.

### Default Build (aws-lc-rs)

Requires **CMake** and **NASM** installed.

```sh
cargo build --release
```

### Alternative Build (ring)

Use this if you prefer the `ring` cryptography backend:

```sh
cargo build --release --no-default-features --features "ring"
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
    2. Configure the DNS server address to match the IP address specified in the `config.json` file for the `serve_addrs` section.

### Setting Up DnsSafeguard as a Windows Service

**Important:** Before creating the service, make sure DnsSafeguard is configured and working correctly.

#### Steps

1. **Open PowerShell as Administrator**
   - Right‑click the Start menu, choose **Windows PowerShell (Admin)**.
   - You need administrator rights to create or manage services.

2. **Create the Service**
   - Replace `"PATH TO DnsSafeguard EXE"` with the actual location of the DnsSafeguard program on your computer.
   - Run this command in PowerShell:
      `sc.exe create DnsSafeguard binPath= "PATH TO DnsSafeguard EXE" start= auto`

   - Example:
     `sc.exe create DnsSafeguard binPath= "C:\Users\Sara\Desktop\DnsSafeguard\DnsSafeguard.exe" start= auto`

3. **Start the Service**
   - Run this command:
     `sc.exe start DnsSafeguard`

4. **Automatic Startup**
   - Once created, the DnsSafeguard service will automatically start every time Windows boots up.

5. **Restart After Configuration Changes**  
   - If you make any changes to the DnsSafeguard configuration file, you must restart the service for the changes to take effect.
   - First, stop the service:
     `sc.exe stop DnsSafeguard`

   - Then, start it again:
     `sc.exe start DnsSafeguard`

#### Managing the Service in Windows (Alternative Way)

You don’t always need PowerShell — Windows also provides a built‑in tool to manage services:

- Press **Windows Key + R** to open the Run dialog.  
- Type `services.msc` and press **Enter**.  
- In the **Services** window, scroll down to find **DnsSafeguard**.  
- From here you can **Start**, **Stop**, or **Restart** the service by right‑clicking it and choosing the option you need.

> 💡 This is a simple way to manage services if you prefer a graphical interface instead of command‑line tools.

### Linux

Follow the same steps as Windows except for step 5: open the `/etc/resolv.conf` file and configure the DNS server address to match the IP address specified in the `config.json` file for the `serve_addrs` section. For example, if `serve_addrs` value is `127.0.0.1`, then the content in `/etc/resolv.conf` must be `nameserver 127.0.0.1`.

## DNS Server

[Go to DNS servers page](/DNS.md)

## Local DoH Server

[Go to local DoH server page](/DOHSERVER.md)

## Configuration File - `config.json`

The `config.json` file is a crucial part of the DnsSafeguard application. It contains the necessary settings to control the behavior of the DNS client.

### Structure

The configuration file is structured in JSON format and includes the following settings:

- `Log`:
  - `level`: Specifies the logging verbosity. Available options: `error`, `warn`, `info`, `debug`, `trace`. Set to null to disable.
  - `file`: Path to the log output file. Set to `null` to disable file logging and enable console output instead. Logging to both file and console simultaneously is not supported. You must choose one.
- `Protocol`: Specifies the protocol used for DNS queries.
  - `h1`: Single HTTP/1.1 Connection.
  - `h1_multi`: Multiple HTTP/1.1 Connection.
  - `h2`: HTTP/2 Connection.
  - `h3`: HTTP/3 Connection.
  - `dot`: DOT Connection (DNS over TLS).
  - `doq`: DoQ Connection (DNS over QUIC).
- `Server Name`: The domain name of the DNS server.
- `IP As SNI`: When enabled, the server name is not used as SNI, which can be a good alternative to the fragmenting method. Some public DNS servers, like Google, support this. Supported protocols include H1, H2, DoT, and H1_multi.
- `Disable Certificate Validation`: This option ignores certificate server name matching, enabling the use of domain fronting. For example, you can use `www.google.com` as the server name, which is not blocked by the Great Firewall (GFW). Many DNS servers, such as Google, Quad9, and NextDNS, support this option. However, Cloudflare does not, as it uses SNI guard. This is the best option for bypassing the GFW. **Disable Fragmenting**.
- `Remote Addrs`: The IP address and port for the DNS server connection.
- `Interface`: Name of the Interface/Adapter to bind to. Use `null` for default.
- `Serve Addrs`: Local UDP address to listen for incoming DNS queries. Use `[::]:53` to enable dual-stack support, but note that network changes may require an application restart. For most setups, `127.0.0.1:53` is recommended.
- `Custom Http Path`: Specify a custom HTTP path for HTTP-based protocols such as H1, H2, and H3. Use `null` for default which is the standard DoH path.
  - Examples: `/jsd3n5nb4/dns-query`, `/user/d618995a10e74acec7ed454ac6e39d6eb/dns-query`.
  - Warning: Custom path must end with `/dns-query`.
- `Http Method`: Values are `GET` and `POST`. GET is more compatible, it consumes more memory. POST, on the other hand, eliminates the need to encode DNS queries in base64url, resulting in lower memory usage. However, it requires two write system calls.
- `Response Timeout`: How long to wait for http response for DoQ, H3 and H1.
- `Connection Keep Alive`: Sends periodic keep-alive signals—such as `GET /` (H2/H3), empty DNS headers (DoT), or empty buffers (DoQ)—at a specified interval in seconds to maintain connections with remote servers that may ignore standard HTTP/2 or QUIC keep-alives; set to `null` to disable.
- `TLS Core`: Default backend is `rustls`, which supports all current features. Alternative TLS backends include `boring` and `native` (SChannel on Windows, Security.framework on macOS, and OpenSSL on other platforms). Fragmentation is not supported. `boring` and `native` are only compatible with `h1`, `h2`, and `dot`.
- `Fragmenting`: The fragmentation method to use during the TLS handshake. [Fragmenting page](/FRAG.md)
- `Noise`: List of UDP noises.
  - `Ntype`: Noise type. Variants include `dns`, `str`, `lsd`, `tracker`, `stun`, `tftp` and `rand`.
  - `Content`: Domain for `dns` ntype. Text for `str` ntype.
  - `Size`: Specifies the length of each noise packet in bytes for `rand` ntype.
  - `Sleep`: Defines the sleep time (in milliseconds) after each UDP noise packet is sent.
- `Quic`: Configuration for QUIC protocol.
  - `Congestion Controller`: The congestion controller algorithm, options are `bbr`, `cubic` and `newreno`.
  - `Keep Alive Interval`: The interval in seconds to keep the connection alive. Use `null` to disable.
  - `Datagram Receive Buffer Size`: Size of the receive buffer for datagrams. Use `null` for default.
  - `Datagram Send Buffer Size`: Size of the send buffer for datagrams. Use `null` for default.
  - `Connecting Timeout`: Specifies the maximum connection timeout duration in seconds.
  - `Packet Threshold`: Maximum reordering in packet number space before FACK style loss detection considers a packet lost. Should not be less than 3, per RFC5681.
  - `Initial MTU`: The initial value to be used as the maximum UDP payload size before running MTU discovery. Must be at least 1200, Use `null` for default.
  - `Min MTU`: The maximum UDP payload size guaranteed to be supported by the network. Must be at least 1200, Use `null` for default.
  - `Crypto Buffer Size`: Maximum quantity of out-of-order crypto layer data to buffer. Use `null` for default.
  - `Stream Receive Window`: Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked. Use `null` for default.
  - `Max Idle Timeout`: Maximum duration in seconds of inactivity to accept before timing out the connection. `null` represents an infinite timeout.
- `H2`:
  - `header_table_size`: This setting informs the peer of the maximum size of the header compression table used to encode header blocks.
  - `max_header_list_size`: This advisory setting informs a peer of the maximum size of header list that the sender is prepared to accept.
  - `initial_connection_window_size`: Indicates the initial window size (in octets) for connection-level flow control for received data.
  - `initial_window_size`: Indicates the initial window size (in octets) for stream-level flow control for received data.
- `Connection`:
  - `H1 Multi Connections`: Number of connections for the `h1 multi` protocol.
  - `Reconnect Sleep`: Duration to sleep before reconnecting (in seconds).
- `Tcp Socket Options`:
  - `Send Buffer Size`: The size (in bytes) of the socket's send buffer. Use `null` for default.
  - `Recv Buffer Size`: The size (in bytes) of the socket's receive buffer. Use `null` for default.
  - `Nodelay`: Disables Nagle's algorithm when set to true. This reduces latency for small packets. Use `null` for default.
  - `Keepalive`: keepalive enables TCP keepalive probes when set to true. Helps detect dead peers and maintain long-lived connections. Use `null` for default.
- `DoH Server`: Local DNS over HTTPS (HTTP/2) server for browsers.
  - `Listen Address`: The IP address and port of the local DoH server (e.g., `127.0.0.1:443`).
  - `ALPN`: Set up the HTTP version to serve. Supported variants are `h2` and `http/1.1`.
  - `Certificate`: Path to the certificate file (e.g., `/path/to/certificate.crt`).
  - `Key`: Path to the key file (e.g., `/path/to/key.key`).
  - `Cache Control`: cache control as response header.
  - `Response Timeout`: List of two durations (in seconds) specifying how long to wait for a response attempt.
  - `Log Errors`: Enable logging DoH sever errors.
- `Runtime`: [Tokio runtime document](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html)
  - `Runtime Mode`: Variants are `Multi` (Multi-threaded runtime) and `Single` (Single-threaded runtime).
  - `Worker Threads`: Number of worker threads used in Multi mode.
  - `Thread Stack Size`: Stack size allocated per thread in Multi mode.
  - `Event Interval`: Number of scheduler ticks after which the scheduler will poll for external events. `null` for default.
  - `Global Queue Interval`: Number of scheduler ticks after which the scheduler will poll the global task queue. `null` for default.
  - `Max Io Events Per Tick`: Enables the I/O driver and configures the max number of events to be processed per tick. `null` for default.
  - `Thread Keep Alive`: Duration a thread remains alive in the blocking pool when idle. By default, the timeout for a thread is set to 10 seconds. `null` for default.
- `Rules`: Block or bypass DNS queries containing specified domains or keywords. [Rules Page](/RULES.md).
- `Overwrite`: Overwrite IPs from DNS responses. [Overwrite Page](/OVERWRITE.md).

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
