# Requirements

- [Mbed TLS 2.28.8](https://www.trustedfirmware.org/projects/mbed-tls/)

## Nix

```sh
nix-shell -p mbedtls_2
```

# Compiling

```sh
$ g++ -o server server.cpp -lmbedcrypto -lmbedtls -lmbedx509
$ g++ -o client client.cpp -lmbedcrypto -lmbedtls -lmbedx509
```
