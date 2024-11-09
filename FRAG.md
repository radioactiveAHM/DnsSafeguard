# TLS Client Hello Fragmentation

This method sends TLS Client Hello messages in various ways to avoid connection blocking based on Server Name Indication (SNI).

## Keywords

- Client Hello (CH)

## Options

- `linear`: Splits CH into 3 packets, sending each in a separate TCP segment with a 50ms interval.
- `random`: Splits CH into random packets, sending each in a separate TCP segment with a random interval between 10-21ms.
- `single`: Splits CH into 2 packets, sending both in a single TCP segment.
- `jump`: Splits CH into 2 packets, sending each packet using 2 TCP segments.
