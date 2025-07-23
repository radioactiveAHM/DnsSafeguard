# TLS Client Hello Fragmentation

This method sends TLS Client Hello messages in various ways to avoid connection blocking based on Server Name Indication (SNI).

## Keywords

- Client Hello (CH)

## Options

- `method`: Fragmenting methods
  - `random`: Splits CH into random packets, sending each in specified separate TCP segments with random intervals.
  - `single`: Splits CH into random packets, sending all in one buffer in specified separate TCP segments with random intervals.
- `sleep_interval`: Sleep interval.
- `fragment_size`: Fragment size.
- `segments`: Number of TCP segments.
