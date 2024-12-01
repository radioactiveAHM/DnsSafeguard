# Local DoH Server

Local DNS over HTTPS (DoH) server supporting HTTP/2 (HTTP/1.1 coming soon). This setup is useful for applications like DnsSafeguard, especially for browsers like Microsoft Edge to enable Encrypted Client Hello (ECH) for enhanced privacy. ECH requires a DoH server to function.

## Usage

To use the local DoH server, you need to provide a key and a system-trusted certificate. Follow these steps to generate them:

1. Create a folder and a file named san.cnf with the following content:

```cnf
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = US
O = Google Trust Services LLC
CN = WR2
[v3_req]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
```

2. Generate the Key File: Run the following command to generate the key file `openssl ecparam -genkey -name prime256v1 -out key.pem`.
3. Generate the Certificate File: Run the following command to generate the certificate file `openssl req -new -x509 -days 36500 -key key.pem -out cert.pem -config san.cnf`.
4. Install the Certificate: install the generated certificate file so the system can trust it.
5. Configure DnsSafeguard: Move the key and certificate files to the DnsSafeguard folder and configure the DnsSafeguard configuration file accordingly.
6. Use the DoH Server: Use the following URL in browsers or applications to connect to the local DoH server `https://127.0.0.1/dns-query{?dns}`
