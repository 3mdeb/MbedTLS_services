#include "common.h"

void initialize_mbedtls(mbedtls_ssl_context &ssl, mbedtls_ssl_config &ssl_conf, mbedtls_x509_crt &cacert, mbedtls_pk_context &key, mbedtls_x509_crt &cert, mbedtls_ctr_drbg_context &ctr_drbg, mbedtls_entropy_context &entropy) {
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_pk_init(&key);
    mbedtls_x509_crt_init(&cert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
}

void cleanup_mbedtls(mbedtls_ssl_context &ssl, mbedtls_ssl_config &ssl_conf, mbedtls_x509_crt &cacert, mbedtls_pk_context &key, mbedtls_x509_crt &cert, mbedtls_ctr_drbg_context &ctr_drbg, mbedtls_entropy_context &entropy) {
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&key);
    mbedtls_x509_crt_free(&cert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void handle_error(int ret, const std::string &msg, int expected) {
    if (ret != expected) {
        std::cerr << msg << " Error code: " << ret << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

std::string get_ssl_verify_result(mbedtls_ssl_context &ssl) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    std::string result;

    if (flags == 0) {
        result = "No verification errors";
    } else {
        result = "Verification errors: ";
        if (flags & MBEDTLS_X509_BADCERT_EXPIRED) result += "Certificate expired ";
        if (flags & MBEDTLS_X509_BADCERT_REVOKED) result += "Certificate revoked ";
        if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) result += "CN mismatch ";
        if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) result += "Certificate not trusted ";
    }

    return result;
}

void debug_callback(void *ctx, int level, const char *file, int line, const char *str) {
    if (level <= *(int *)ctx) {
        std::cerr << file << ":" << line << " (" << level << "): " << str;
    }
}
