# DnsSafeguard

![DnsSafeguard](./sample-256.png)

DnsSafeguard is a fast and secure DNS client written in Rust, designed to intercept DNS queries over a UDP socket and Dns over HTTPS (DoH) to securely transmit them to a DNS server using DNS over HTTPS/TLS/QUIC (DoH/DoT/DoQ) protocols. By leveraging TLS client hello fragmentation and UDP Noise, it successfully bypasses the Great Firewall (GFW) censorship.

> [!CAUTION]
> DNSSafeGuard is designed for **client use only**. Do **not** run it on public servers, as it is currently vulnerable to **DDoS attacks**. Deploying it on internet-facing systems may result in service disruption or downtime.

## Struct

![Graph](./DnsSafeguard%20graph.jpg)

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
- [x] HTTP/1.1 Support
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
- [x] Multi Server

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

#### **Log**

- **level**
  Defines the verbosity of log output. Supported values:
  `error`, `warn`, `info`, `debug`, `trace`.
  Set to `null` to disable logging entirely.
- **file**
  Path to the log output file.
  Set to `null` to disable file logging and output logs to console instead.
  **Note:** Logging to both file and console simultaneously is not supported. Choose one.

---

#### **Servers**

Configuration for upstream DNS servers.

- **protocol**
  DNS transport protocol:

  - `h1` — DNS over HTTPS (HTTP/1.1)
  - `h2` — DNS over HTTPS (HTTP/2)
  - `h3` — DNS over HTTPS (HTTP/3)
  - `dot` — DNS over TLS
  - `doq` — DNS over QUIC
- **remote_addrs**
  IP address and port of the DNS server.
- **hostname**
  The server's domain name.
- **path**
  DoH path. Use `/dns-query` for default.
- **http_method**
  Request method for DoH: `GET` or `POST`.

  - `GET` — more compatible, but uses more memory.
  - `POST` — more efficient, no base64url encoding required.
- **sni**
  The Server Name Indication sent during TLS handshake.
- **ip_as_sni**
  When `true`, use the server IP instead of the hostname as SNI.
  Useful for bypassing censorship. Supported in `h1`, `h2` and `dot`.
- **disable_certificate_validation**
  Skips hostname verification in the TLS handshake.
  Enables domain fronting (e.g., using `www.google.com` as SNI).
  Supported by Google, Quad9, NextDNS.
  **Cloudflare does not support this due to SNI Guard.**
  Recommended when bypassing DPI/GFW. Disable fragmenting when using this option.

---

#### **General Settings**

- **serve_addrs**
  Local UDP address to receive DNS queries.
  Example: `127.0.0.1:53` is recommended for local resolvers.
  Use `[::]:53` for dual-stack; may require application restart after network changes.
- **interface**
  Network interface name to bind. Use `null` for default.
- **response_timeout**
  Maximum wait time (seconds) for responses.
- **connection_keep_alive**
  Interval for sending keep-alive packets (seconds).
  Set to `null` to disable.
- **reconnect_sleep**
  Time to wait (seconds) before reconnecting.
- **pipe_capacity**
  Internal pipeline buffer size.
- **tls_core**
  TLS backend:

  - `rustls` — default, supports all features including fragmenting
  - `boring` — supports `h1`, `h2`, and `dot`
  - `native` — platform TLS (SChannel/Security.framework/OpenSSL); supports `h1`, `h2`, `dot`

---

#### **Fragmenting**

Controls TLS handshake fragmentation. Useful for bypassing DPI.

- **enable** — Enable or disable fragmentation.
- **method** — Current supported method: `single`.
- **sleep_interval** — Delay between fragments (ms).
- **fragment_size** — Size range of each fragment (bytes).
- **segments** — Number of fragments.

---

#### **Noise**

Injects UDP noise packets to mask query patterns.

- **ntype** — Noise type (`dns`, `str`, `lsd`, `tracker`, `stun`, `tftp`, `rand`, `socks5`, `turn`, `dht`).
- **content** — Domain for `dns`, text for `str`.
- **size** — Size range (bytes) for `rand`.
- **sleep** — Delay between packets (ms).

---

#### **QUIC**

QUIC protocol configuration for `doq` and `h3`.

- **congestion_controller** — `bbr`, `cubic`, or `newreno`.
- **keep_alive_interval** — Interval (seconds); `null` to disable.
- **datagram_receive_buffer_size** — Receive buffer size; `null` for default.
- **datagram_send_buffer_size** — Send buffer size; `null` for default.
- **connecting_timeout** — Max connection timeout (seconds).
- **packet_threshold** — Reordering threshold, must be ≥ 3 (RFC 5681).
- **initial_mtu** — Initial MTU; ≥ 1200; `null` for default.
- **min_mtu** — Minimum guaranteed MTU; ≥ 1200; `null` for default.
- **crypto_buffer_size** — Buffer for out-of-order crypto data.
- **stream_receive_window** — Max unacknowledged bytes per stream.
- **max_idle_timeout** — Idle timeout (seconds); `null` means infinite.

---

#### **HTTP/2 (H2)**

Advanced HTTP/2 protocol tuning.

- **header_table_size** — Size of HPACK header table.
- **max_header_list_size** — Maximum acceptable header list size.
- **initial_connection_window_size** — Connection-level flow control window.
- **initial_window_size** — Stream-level flow control window.
- **max_pending_accept_reset_streams** — Maximum pending reset streams.
- **max_concurrent_reset_streams** — Maximum active reset streams.
- **max_frame_size** — Maximum frame size (default: 16777214).

---

#### **TCP Socket Options**

- **send_buffer_size** — Custom send buffer size (bytes).
- **recv_buffer_size** — Custom receive buffer size (bytes).
- **nodelay** — Disable Nagle’s algorithm to reduce latency.
- **keepalive** — Enable TCP keepalive probes.

---

#### **DoH Server (Local)**

Local DNS-over-HTTPS server for browsers or system resolvers.

- **enable** — Enable or disable local DoH server.
- **listen_address** — Example: `127.0.0.1:443`.
- **alpn** — Supported protocols: `h2`, `http/1.1`.
- **certificate** — Path to certificate file.
- **key** — Path to private key file.
- **cache_control** — Cache-Control HTTP response header.
- **response_timeout** — Response wait time (seconds).
- **log_errors** — Log DoH server errors when enabled.

---

#### **Runtime**

Tokio runtime configuration for advanced tuning.

- **runtime_mode** — `Multi` (multi-threaded) or `Single` (single-threaded).
- **worker_threads** — Worker thread count (Multi mode only).
- **thread_stack_size** — Per-thread stack size.
- **event_interval** — Scheduler external-event polling frequency.
- **global_queue_interval** — Scheduler global task queue polling frequency.
- **max_io_events_per_tick** — Maximum I/O events processed per tick.
- **thread_keep_alive** — Idle timeout for worker threads (default: 10s).

---

#### **Rules**

Filtering rules for DNS queries.

- **options** — List of domains or keywords.
- **target**

  - `block`: Blocks matching queries.
  - (Other rule types documented in `/RULES.md`.)

---

#### **Overwrite**

Rules for overriding IPs returned in DNS responses.
See `/OVERWRITE.md` for full specification.

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
