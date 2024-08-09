# TLS Mutual Authentication

This demo covers setting up a TLS-secured server service, generating a
Certificate Authority (CA), server and client certificates, and demonstrating
both successful and failed authentication due to certificate validation.

The demo currently doesn't utilize MbedTLS/PSA Crypto API and certificates are
generated by OpenSSL beforehand.

## Mutual Authentication

### Server Authenticating the Client

The server requires and verifies the client's certificate. When a client
attempts to connect to the server, it presents its certificate. The server then
uses the CA certificate (which it trusts) to verify that the client's
certificate was signed by the trusted CA. If the client's certificate is valid
and trusted, the server proceeds with the connection. This process ensures that
only clients with certificates issued by the trusted CA can establish
connections to the server.

### Client Verifying the Server's Authenticity

Similarly, the client also verifies the server's authenticity during the TLS
handshake. When the server presents its certificate to the client, the client
uses the CA certificate (that it has been configured to trust) to verify that
the server's certificate was indeed signed by the trusted CA. This verification
process ensures that the client is talking to the correct server and not an
impostor. If the server's certificate cannot be verified or is not trusted
(for example, if it was signed by a different CA), the client will terminate
the connection attempt.

## Prerequisites

- [Mbed TLS 2.28.8](https://www.trustedfirmware.org/projects/mbed-tls/)
- Tested with [OpenSSL 3.1.0](https://openssl-library.org/post/2023-03-07-openssl3.1release/)
  and [OpenSSL 3.2.0](https://openssl-library.org/post/2023-11-06-openssl32/)

If you have `nix` installed you can easily enter a shell with dependencies with:

```sh
nix-shell -p mbedtls_2
```

## Scenario

### Step 1. Running the Server and Client

#### Getting the repo

```sh
git clone https://github.com/3mdeb/MbedTLS_services.git
cd MbedTLS_services
```

#### Compiling the `mbedtls_script_server` and `mbedtls_script_client`

Simply run `make` from the top of the repository

```sh
make
```

When developing/testing you can run `make clean` to quickly remove all binaries

```sh
make clean
```

Two binaries are produced `mbedtls_script_server` and `mbedtls_script_client`
which we'll use in testing scenarios.

### Step 2: Generating the Certificate Authority (CA)

First, create a CA that will sign the server and client certificates.

#### Create the CA's self-signed certificate:

Modern versions of TLS and their implementations in libraries
require the use of Subject Alternative Name (SAN) for hostname
verification instead of relying solely on the Common Name (CN) field. This
change improves security and flexibility in certificate handling.

It's recommended to store all certificates in the `keys` directory of repo.

```sh
cd keys
```

#### Generate the CA's private key:
```sh
openssl genrsa -out ca_key.pem 4096
```

The `ca.conf` file used in the command to create CA should contain:

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
# Configuration ...
dir = .
certificate = $dir/ca_cert.pem
private_key = $dir/ca_key.pem
# Other settings ...

[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
# Distinguished Name (DN) details...
CN = My Test CA

[ v3_ca ]
# CA-specific extensions...
```

```sh
openssl req -new -x509 -days 3650 -config ca.conf -key ca_key.pem -out ca_cert.pem
```

### Step 3: Generating Server and Client Certificates

#### Generate the server/client certificate signing request (CSR) and sign it:

Repeat the steps for the client certificate, substituting "client" for "server" in the filenames.
Certificate Configuration (cert.conf).

The cert.conf file should include:

```ini
[ req ]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
```

##### Server

```sh
$ openssl genrsa -out server_key.pem 4096
$ openssl req -new -key server_key.pem -out server_csr.pem -config cert.conf
$ openssl x509 -req -days 365 -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out server_cert.pem -extfile cert.conf -extensions req_ext
```

##### Client

```sh
$ openssl genrsa -out client_key.pem 4096
$ openssl req -new -key client_key.pem -out client_csr.pem -config cert.conf
$ openssl x509 -req -days 365 -in client_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -extfile cert.conf -extensions req_ext
```

## Testing Scenarios

mTLS makes it that both the server and client verify the certificates of each
other against the CA. Thus the server knows that the client is authorized
for access and the client knows that the server is not an impostor.

### Successful Authentication

#### `mbedtls_script_server`

```sh
$ ./mbedtls_script_server --ca-certificate keys/ca_cert.pem --certificate keys/server_cert.pem --private-key keys/server_key.pem
Initializing seed CTR-DRBG ...
Loading CA certificate...
Loading server certificate...
Loading server private key...
Setting up SSL configuration...
Setting up SSL context...
Binding to port...
Server is running. Waiting for connections...
Client connected. Setting up SSL...
SSL handshake successful
```

#### `mbedtls_script_client`

```sh
$ ./mbedtls_script_client --ca-certificate keys/ca_cert.pem --certificate keys/client_cert.pem --private-key keys/client_key.pem --server localhost
Initializing seed CTR-DRBG...
Loading CA certificate...
Loading client certificate...
Loading client private key...
Setting up SSL configuration...
Setting up SSL context...
Connecting to server...
Starting handshake...
Handshake successful!
```

### Failed authentication

Generate an "invalid" client certificate signed by an untrusted CA and attempt
to connect:

#### Generate the untrusted CA and client certificate

```sh
$ openssl genrsa -out bad_ca_key.pem 4096
$ openssl req -new -x509 -days 3650 -config ca.conf -key bad_ca_key.pem -out bad_ca_cert.pem
$ openssl genrsa -out bad_key.pem 4096
$ openssl req -new -key bad_key.pem -out bad_csr.pem -config cert.conf
$ openssl x509 -req -days 365 -in bad_csr.pem -CA bad_ca_cert.pem -CAkey bad_ca_key.pem -CAcreateserial -out bad_cert.pem -extfile cert.conf -extensions req_ext
```
#### Correct server certificate and incorrect client certificate - access refused

##### `mbedtls_script_server`

```sh
$ ./mbedtls_script_server --ca-certificate keys/ca_cert.pem --certificate keys/server_cert.pem --private-key keys/server_key.pem
Initializing seed CTR-DRBG ...
Loading CA certificate...
Loading server certificate...
Loading server private key...
Setting up SSL configuration...
Setting up SSL context...
Binding to port...
Server is running. Waiting for connections...
Client connected. Setting up SSL...
SSL handshake failed. Error code: -9984
Certificate verification result: Certificate not trusted
```

##### `mbedtls_script_client`

```sh
$ ./mbedtls_script_client --ca-certificate keys/ca_cert.pem --certificate keys/bad_cert.pem --private-key keys/bad_key.pem --server localhost
Initializing seed CTR-DRBG...
Loading CA certificate...
Loading client certificate...
Loading client private key...
Setting up SSL configuration...
Setting up SSL context...
Connecting to server...
Starting handshake...
Handshake failed. Error code: -80
No verification errors
```

#### Incorrect server certificate - client doesn't try to connect

##### `mbedtls_script_server`

```sh
$ ./mbedtls_script_server --ca-certificate keys/bad_ca_cert.pem --certificate keys/bad_cert.pem --private-key keys/bad_key.pem
Initializing seed CTR-DRBG ...
Loading CA certificate...
Loading server certificate...
Loading server private key...
Setting up SSL configuration...
Setting up SSL context...
Binding to port...
Server is running. Waiting for connections...
Client connected. Setting up SSL...
SSL handshake failed. Error code: -80
No certificate verification errors
```

##### `mbedtls_script_client`

```sh
$ ./mbedtls_script_client --ca-certificate keys/ca_cert.pem --certificate keys/client_cert.pem --private-key keys/client_key.pem --server localhost
Initializing seed CTR-DRBG...
Loading CA certificate...
Loading client certificate...
Loading client private key...
Setting up SSL configuration...
Setting up SSL context...
Connecting to server...
Starting handshake...
Handshake failed. Error code: -9984
Certificate verification errors: Certificate not trusted
```
