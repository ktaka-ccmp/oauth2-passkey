#!/bin/bash

# Define filenames and validity period
PRIVATE_KEY="key.pem"
CERTIFICATE="cert.pem"
CONFIG_FILE="openssl.cnf"
DAYS_VALID=3650

# Create OpenSSL configuration file with SANs
cat > $CONFIG_FILE <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Generate private key and self-signed certificate
openssl req -x509 -nodes -newkey rsa:2048 -keyout $PRIVATE_KEY -out $CERTIFICATE \
-days $DAYS_VALID -config $CONFIG_FILE

# Cleanup configuration file
rm $CONFIG_FILE

echo "Done! Files generated:"
echo "  Private Key: $PRIVATE_KEY"
echo "  Certificate: $CERTIFICATE"
