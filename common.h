#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <cstdlib>
#include <string>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <psa/crypto.h>

#define DEFAULT_PORT "4433"

void initialize_mbedtls(mbedtls_ssl_context &ssl, mbedtls_ssl_config &ssl_conf, mbedtls_x509_crt &cacert, mbedtls_pk_context &key, mbedtls_x509_crt &cert, mbedtls_ctr_drbg_context &ctr_drbg, mbedtls_entropy_context &entropy);
void cleanup_mbedtls(mbedtls_ssl_context &ssl, mbedtls_ssl_config &ssl_conf, mbedtls_x509_crt &cacert, mbedtls_pk_context &key, mbedtls_x509_crt &cert, mbedtls_ctr_drbg_context &ctr_drbg, mbedtls_entropy_context &entropy);
void handle_error(int ret, const std::string &msg, int expected = 0, bool print_ret = true);
std::string get_ssl_verify_result(mbedtls_ssl_context &ssl);
void debug_callback(void *ctx, int level, const char *file, int line, const char *str);
std::string get_psa_error_message(psa_status_t status);
void handle_psa_error(psa_status_t status, const std::string &msg);

#endif
