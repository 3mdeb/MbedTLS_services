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
    if (ret != expected && ret < 0) {
        std::cerr << msg;
        if (print_ret) {
            std::cerr << std::endl << " Error code: " << ret;
        }
        std::cerr << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

int init_pkcs11_rsa_ctx(mbedtls_rsa_context *rsa_ctx, std::string slot_id,
		std::string user_pin, std::string subject, CK_BYTE_PTR key_id,
		CK_BYTE key_id_lenght){
    int ret = 0;

    // Pass PKCS#11 info to RSA context structure:
    rsa_ctx->SlotID = (CK_SLOT_ID)(slot_id.c_str()[0] - 48);
    rsa_ctx->UserPinLen = user_pin.length();
    rsa_ctx->UserPin = (CK_UTF8CHAR_PTR)mbedtls_calloc(rsa_ctx->UserPinLen, sizeof(CK_UTF8CHAR));
    if (rsa_ctx->UserPin == NULL){
        handle_error(1, "Failed to allocate memory for PKCS#11 user pin.");
        ret = 1;
    }
    memcpy(rsa_ctx->UserPin, user_pin.c_str(), rsa_ctx->UserPinLen);

    rsa_ctx->SubjectLength = subject.length();
    rsa_ctx->Subject = (CK_BYTE_PTR)mbedtls_calloc(rsa_ctx->SubjectLength, sizeof(CK_BYTE));
    if (rsa_ctx->Subject == NULL){
        handle_error(1, "Failed to allocate memory for PKCS#11 key subject.");
        ret = 1;
    }
    memcpy(rsa_ctx->Subject, subject.c_str(), rsa_ctx->SubjectLength);

    rsa_ctx->IdLen = key_id_lenght;
    rsa_ctx->Id = (CK_BYTE_PTR)mbedtls_calloc(rsa_ctx->IdLen, sizeof(CK_BYTE));
    if (rsa_ctx->Id == NULL){
        handle_error(1, "Failed to allocate memory for PKCS#11 key id");
        ret = 1;
    }
    memcpy(rsa_ctx->Id, key_id, rsa_ctx->IdLen);

    return ret;
}

int generate_keypair(mbedtls_pk_context *pk_ctx, std::string slot_id,
		std::string user_pin, std::string subject, CK_BYTE_PTR key_id,
		CK_BYTE key_id_length, int (*f_rng)(void *, unsigned char *, size_t),
		void *p_rng){
    int ret = 0;
    mbedtls_rsa_context *rsa_ctx;

    // PK should have type MBETLS_PK_RSA to continue:
    switch (mbedtls_pk_get_type(pk_ctx)){
        case MBEDTLS_PK_RSA:
	    break;
        default:
	    ret = 1;
	    handle_error(ret, "PK context is not of type MBETLS_PK_RSA");
    }

    // Extract key handler to generate and save RSA key:
    rsa_ctx = mbedtls_pk_rsa(*pk_ctx);
    if (rsa_ctx == NULL){
        ret = 1;
        handle_error(ret, "Failed to get RSA context");
    }

    ret = init_pkcs11_rsa_ctx(rsa_ctx, slot_id, user_pin, subject, key_id,
		    key_id_length);

    // Generate the keys:
    ret = mbedtls_rsa_gen_key(rsa_ctx, f_rng, p_rng,
		    KEY_SIZE, PUBLIC_EXPONENT);

    return 0;
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
