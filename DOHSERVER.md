# Local DoH Server

A local DNS over HTTPS (DoH) server supporting HTTP/2 and HTTP/1.1 (POST and GET). This setup enables applications like DnsSafeguard to provide enhanced privacy features, such as Encrypted Client Hello (ECH) in browsers like Microsoft Edge, which requires a DoH server to function.

## Prerequisites

- OpenSSL installed on your system
- Administrative access to install certificates

## Setup Instructions

### 1. Generate SSL Certificate and Key

Create a configuration folder and generate the necessary cryptographic files:

```bash
# Create a dedicated directory for your certificate files
mkdir doh-certificates
cd doh-certificates
```

Create `san.cnf` with the following content:

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

Generate the cryptographic files:

```bash
# Generate elliptic curve private key
openssl ecparam -genkey -name prime256v1 -out key.pem

# Generate self-signed certificate (valid for 1 year)
openssl req -new -x509 -days 365 -key key.pem -out cert.crt -config san.cnf
```

### 2. Install Certificate as Trusted Root (Windows 11)

For Windows 11 to trust your local DoH server, install the certificate as follows:

1. **Locate the Certificate File**: Right-click on `cert.crt` and select **Install Certificate**
2. **Store Location**: Select **Local Machine** → Click **Next**
3. **Certificate Store**: Choose **Place all certificates in the following store**
4. **Browse**: Select **Trusted Root Certification Authorities** → Click **OK**
5. **Complete**: Click **Next** → **Finish** to complete the installation

**Security Note**: Only install certificates from trusted sources. Since you generated this certificate yourself, it's safe for local use.

### 3. Configure DnsSafeguard

1. Copy `key.pem` and `cert.crt` to your DnsSafeguard configuration directory
2. Update the DnsSafeguard configuration file to reference these files
3. Restart DnsSafeguard to apply the changes

### 4. Connect to Your DoH Server

Use the following endpoints to connect to your local DoH server:

- **GET requests**: `https://127.0.0.1/dns-query{?dns}`
- **POST requests**: `https://127.0.0.1/dns-query`

## Verification

To verify your setup is working correctly:

1. Check that DnsSafeguard is running without errors
2. Test the DoH endpoint using a tool like `curl`:

   ```bash
   curl -H "accept: application/dns-json" "https://127.0.0.1/dns-query?name=example.com&type=A"
   ```

## Troubleshooting

- **Certificate errors**: Ensure the certificate is installed in the **Trusted Root Certification Authorities** store
- **Connection refused**: Verify DnsSafeguard is running and configured to use the correct certificate files
- **Browser trust issues**: Some browsers may require additional steps to trust local certificates

## Security Considerations

- Keep your `key.pem` file secure and never share it
- The generated certificate is only valid for localhost/127.0.0.1
