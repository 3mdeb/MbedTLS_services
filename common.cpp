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

void handle_error(int ret, const std::string &msg, int expected, bool print_ret) {
    if (ret != expected) {
        std::cerr << msg;
        if (print_ret) {
            std::cerr << std::endl << " Error code: " << ret;
        }
        std::cerr << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

std::string get_ssl_verify_result(mbedtls_ssl_context &ssl) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    std::string result;

    if (flags == 0) {
        result = "No certificate verification errors";
    } else {
        result = "Certificate verification errors: ";
        if (flags & MBEDTLS_X509_BADCERT_EXPIRED) result += "Certificate expired ";
        if (flags & MBEDTLS_X509_BADCERT_REVOKED) result += "Certificate revoked ";
        if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) result += "CN mismatch ";
        if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) result += "Certificate not trusted ";
        if (flags & MBEDTLS_X509_BADCRL_NOT_TRUSTED) result += "CRL not trusted ";
        if (flags & MBEDTLS_X509_BADCRL_EXPIRED) result += "CRL expired ";
        if (flags & MBEDTLS_X509_BADCERT_MISSING) result += "Certificate missing ";
        if (flags & MBEDTLS_X509_BADCERT_SKIP_VERIFY) result += "Verification skipped ";
        if (flags & MBEDTLS_X509_BADCERT_OTHER) result += "Other reason ";
        if (flags & MBEDTLS_X509_BADCERT_FUTURE) result += "Certificate validity starts in the future ";
        if (flags & MBEDTLS_X509_BADCRL_FUTURE) result += "CRL is from the future ";
        if (flags & MBEDTLS_X509_BADCERT_KEY_USAGE) result += "Key usage mismatch ";
        if (flags & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE) result += "Extended key usage mismatch ";
        if (flags & MBEDTLS_X509_BADCERT_NS_CERT_TYPE) result += "NS cert type mismatch ";
        if (flags & MBEDTLS_X509_BADCERT_BAD_MD) result += "Unacceptable hash ";
        if (flags & MBEDTLS_X509_BADCERT_BAD_PK) result += "Unacceptable PK alg ";
        if (flags & MBEDTLS_X509_BADCERT_BAD_KEY) result += "Unacceptable key ";
        if (flags & MBEDTLS_X509_BADCRL_BAD_MD) result += "CRL unacceptable hash ";
        if (flags & MBEDTLS_X509_BADCRL_BAD_PK) result += "CRL unacceptable PK alg ";
        if (flags & MBEDTLS_X509_BADCRL_BAD_KEY) result += "CRL unacceptable key ";
    }

    return result;
}

void debug_callback(void *ctx, int level, const char *file, int line, const char *str) {
    if (level <= *(int *)ctx) {
        std::cerr << file << ":" << line << " (" << level << "): " << str;
    }
}

std::string get_psa_error_message(psa_status_t status) {
    switch (status) {
        case PSA_SUCCESS:
            return "Success";
        case PSA_ERROR_ALREADY_EXISTS:
            return "Key already exists";
        case PSA_ERROR_NOT_SUPPORTED:
            return "Not supported";
        case PSA_ERROR_INVALID_ARGUMENT:
            return "Invalid argument";
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return "Insufficient memory";
        case PSA_ERROR_INSUFFICIENT_STORAGE:
            return "Insufficient storage";
        case PSA_ERROR_COMMUNICATION_FAILURE:
            return "Communication failure";
        case PSA_ERROR_DATA_CORRUPT:
            return "Data corrupt";
        case PSA_ERROR_DATA_INVALID:
            return "Data invalid";
        case PSA_ERROR_STORAGE_FAILURE:
            return "Storage failure";
        case PSA_ERROR_HARDWARE_FAILURE:
            return "Hardware failure";
        case PSA_ERROR_CORRUPTION_DETECTED:
            return "Corruption detected";
        case PSA_ERROR_BAD_STATE:
            return "Bad state, library not initialized";
        default:
            return "Unknown error code";
    }
}

void handle_psa_error(psa_status_t status, const std::string &msg) {
    if (status != PSA_SUCCESS) {
        std::cerr << msg << std::endl << "Error Code: " << status << " -> " << get_psa_error_message(status) << std::endl;
        std::exit(EXIT_FAILURE);
    }
}
