# TLS Client Hello Fragmentation

This method sends TLS Client Hello messages in various ways to avoid connection blocking based on Server Name Indication (SNI).

## Keywords

- Client Hello (CH)

## Options

- `method`: Fragmenting methods
  - `random`: Splits CH into random packets, sending each in specified separate TCP segments with random intervals.
  - `single`: Splits CH into random packets, sending all in one buffer in specified separate TCP segments with random intervals.
- `sleep_interval_min`: Minimum sleep interval.
- `sleep_interval_max`: Maximum sleep interval.
- `fragment_size_min`: Minimum fragment size.
- `fragment_size_max`: Maximum fragment size.
- `segments`: Number of TCP segments.
