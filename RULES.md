# Rules

## Rules Object

The `rules` object can either be `null` or a list of rule objects.

```json
"rules": null
```

OR

```json
"rules": []
```

## Rule Object

A rule object consists of two main components:

- `options`: A list of keywords or domains.
- `target`: Can either be a `block`, `dns`, or `ip` object.

Example:

```json
"options": ["google.com", "ads"]
```

### Block Object

The `block` object specifies which DNS queries should be blocked.

- If `null`, all DNS queries matching the options are blocked.
- If it contains a list of record types, only those specific types are blocked.

Examples:

```json
"block": null
```

OR

```json
"block": ["A", "TXT"]
```

### DNS Object

The `dns` object specifies a DNS server to which queries should be bypassed. The value must be in the format of `udp ip port`.

Example:

```json
"dns": "1.1.1.1:53"
```

### IP Object

The `ip` object responds to the DNS query with the provided IP. The value must be a valid IP, both IPv4 and IPv6 are supported.

Example:

```json
"ip": ["192.168.2.1", null]
```

with IPv6

```json
"ip": ["127.0.0.1", "::1"]
```

## Example Configuration

Here's an example configuration for the `rules` object:

```json
"rules": [
  // Block all DNS queries containing keywords in the options object
  {
    "options": [
      "googlesyndication",
      "analytic",
      "googletagmanager"
    ],
    "target": {
      "block": null
    }
  },
  // Block only AAAA (IPv6) DNS queries containing domains in the options object
  {
    "options": [
      "google.com",
      "x.com"
    ],
    "target": {
      "block": ["AAAA"]
    }
  },
  // Bypass DNS queries containing domains in the options object to 8.8.8.8:53 (Google plaintext DNS server)
  {
    "options": [
      "rust-lang.org",
      "crates.io"
    ],
    "target": {
      "dns": "8.8.8.8:53"
    }
  },
  // Respond to DNS queries containing domains in the options object with the IP 192.168.2.1
  {
    "options": [
      "router.com"
    ],
    "target": {
      "ip": ["192.168.2.1", null]
    }
  },
    // Respond to DNS queries containing domains in the options object with both IP versions
  {
    "options": [
      "localhost.com"
    ],
    "target": {
      "ip": ["127.0.0.1", "::1"]
    }
  }
]
```
