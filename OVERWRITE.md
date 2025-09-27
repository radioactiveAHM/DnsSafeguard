# DNS Response Overwrite Configuration

## Overview

The `overwrite` field defines rules for modifying IP addresses in DNS responses. When a DNS query returns an IP address matching one of the specified "options", it will be replaced with the corresponding "target" address.

## Configuration Format

The `overwrite` field accepts either:

- `null` (no overwrite rules)
- An array of overwrite rule objects

**Examples:**

```json
"overwrite": null
```

```json
"overwrite": []
```

## Overwrite Rule Object Specification

Each rule defines IP address replacement patterns:

### Properties

- **`options`** (array of strings): IP addresses that will be replaced in DNS responses
  - Can include IPv4 and/or IPv6 addresses
  - These are the addresses returned by DNS queries that will be modified

- **`target`** (array of strings): Replacement IP addresses
  - Format: `["IPv4_address", "IPv6_address"]`
  - IPv6 address is optional (can be `null`)
  - Must contain exactly two elements

## Examples

### Basic IPv4 Replacement

Replace Cloudflare DNS IP with localhost:

```json
{
    "options": ["1.1.1.1"],
    "target": ["127.0.0.1", null]
}
```

### Dual-Stack Replacement

Replace both IPv4 and IPv6 addresses with local equivalents:

```json
{
    "options": ["1.1.1.1", "2606:4700:4700::1111"],
    "target": ["127.0.0.1", "::1"]
}
```

### Multiple IP Replacement

Replace multiple Google DNS IPs with localhost:

```json
{
    "options": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    "target": ["127.0.0.1", "::1"]
}
```

## Behavior

- When a DNS response contains an IP address listed in `options`, that IP will be replaced with the corresponding address from `target`
- Replacement maintains IP protocol version (IPv4→IPv4, IPv6→IPv6)
- The `target` array must always have two elements; use `null` for unused protocol versions
- Rules are evaluated in order; the first matching rule applies

**Note:** The IP addresses shown (1.1.1.1, 8.8.8.8, etc.) are examples of public DNS servers that could be replaced with local or custom endpoints.
