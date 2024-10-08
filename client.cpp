#include "common.h"

void print_help(const std::string& binary_name) {
    std::cout << "Usage: " << binary_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --server <address>      Server address (required)\n";
    std::cout << "  --ca-certificate <file> CA certificate file (required)\n";
    std::cout << "  --certificate <file>    Client certificate file (required)\n";
    std::cout << "  --private-key <file>    Client private key file (required)\n";
    std::cout << "  -p <port>               Port to connect to (default: 4433)\n";
    std::cout << "  -v, -vv, -vvv, -vvvv    Set verbosity level (default: 0)\n";
    std::cout << "  -h, --help              Show this help message\n";
}

int main(int argc, char *argv[]) {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context key;
    mbedtls_x509_crt cert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret;
    int verbosity = 0;
    std::string server_addr;
    std::string port = DEFAULT_PORT;
    std::string ca_cert_file;
    std::string client_cert_file;
    std::string client_key_file;

    // Get binary name for print_help
    std::string binary_name = argv[0];

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(binary_name);
            return 0;
        } else if (arg == "-v") {
            verbosity = 1;
        } else if (arg == "-vv") {
            verbosity = 2;
        } else if (arg == "-vvv") {
            verbosity = 3;
        } else if (arg == "-vvvv") {
            verbosity = 4;
        } else if (arg == "-p" && i + 1 < argc) {
            port = argv[++i];
        } else if (arg == "--server" && i + 1 < argc) {
            server_addr = argv[++i];
        } else if (arg == "--ca-certificate" && i + 1 < argc) {
            ca_cert_file = argv[++i];
        } else if (arg == "--certificate" && i + 1 < argc) {
            client_cert_file = argv[++i];
        } else if (arg == "--private-key" && i + 1 < argc) {
            client_key_file = argv[++i];
        } else {
            std::cerr << "Unexpected argument: " << arg << std::endl;
            print_help(binary_name);
            return 1;
        }
    }

    if (server_addr.empty() || ca_cert_file.empty() || client_cert_file.empty() || client_key_file.empty()) {
        std::cerr << "Required argument missing.\n";
        print_help(binary_name);
        return 1;
    }

    initialize_mbedtls(ssl, ssl_conf, cacert, key, cert, ctr_drbg, entropy);

    // Initialize RNG
    std::cout << "Initializing seed CTR-DRBG..." << std::endl;
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    handle_error(ret, "Failed to seed CTR-DRBG.");

    std::cout << "Loading CA certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&cacert, ca_cert_file.c_str());
    handle_error(ret, "Failed to parse CA certificate.");

    std::cout << "Loading client certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&cert, client_cert_file.c_str());
    handle_error(ret, "Failed to parse client certificate.");

    std::cout << "Loading client private key..." << std::endl;
    ret = mbedtls_pk_parse_keyfile(&key, client_key_file.c_str(), NULL);
    handle_error(ret, "Failed to parse client private key.");

    std::cout << "Setting up SSL configuration..." << std::endl;
    ret = mbedtls_ssl_config_defaults(&ssl_conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    handle_error(ret, "Failed to configure SSL.");

    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_own_cert(&ssl_conf, &cert, &key);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);  // Set RNG

    // Set debug callback and verbosity level
    mbedtls_ssl_conf_dbg(&ssl_conf, debug_callback, &verbosity);
    mbedtls_debug_set_threshold(verbosity);

    std::cout << "Setting up SSL context..." << std::endl;
    ret = mbedtls_ssl_setup(&ssl, &ssl_conf);
    handle_error(ret, "Failed to set up SSL context.");

    std::cout << "Connecting to server..." << std::endl;
    mbedtls_net_init(&server_fd);
    ret = mbedtls_net_connect(&server_fd, server_addr.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP);
    handle_error(ret, "Failed to connect to server.");

    std::cout << "Starting handshake..." << std::endl;
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ret = mbedtls_ssl_handshake(&ssl);
    if (ret != 0) {
        std::cerr << "Handshake failed. Error code: " << ret << std::endl;
        std::cerr << get_ssl_verify_result(ssl) << std::endl;
    } else {
        std::cout << "Handshake successful!" << std::endl;
    }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    cleanup_mbedtls(ssl, ssl_conf, cacert, key, cert, ctr_drbg, entropy);

    return 0;
}
