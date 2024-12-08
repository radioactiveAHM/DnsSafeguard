# DNS Servers

* Keywords: DNS over HTTPS(DoH), DNS over TLS(DoT), DNS over QUIC(DoQ)
* Standard Ports: DoH: `443`, DoT & DoQ: `853`

## Cloudflare

* Addresses: `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001`
* You can also use other cloudflare cdn IPs.
* SNI: DoH `cloudflare-dns.com`, DoT & DoQ `one.one.one.one`

***

## Google

* Addresses: `8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844`
* SNI: `dns.google`

***

## Adguard

* Addresses: `94.140.14.14`, `94.140.15.15`, `2a10:50c0::ad1:ff`, `2a10:50c0::ad2:ff`
* SNI: `dns.adguard-dns.com`

***

## Quad9

* Addresses: `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`
* SNI: `dns.quad9.net`

***

## Cleanbrowsing

* Addresses: `185.228.168.9`, `185.228.169.9`, `2a0d:2a00:1::2`, `2a0d:2a00:2::2`
* SNI: `security-filter-dns.cleanbrowsing.org`

## NextDns

* Addresses: `45.90.28.26`, `45.90.30.26`, `2a07:a8c0::a1:8f24`, `2a07:a8c1::a1:8f24`
* SNI: `dns.nextdns.io`
