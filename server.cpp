#include "common.h"

void print_help(const std::string& binary_name) {
    std::cout << "Usage: " << binary_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --ca-certificate <file> CA certificate file (required)\n";
    std::cout << "  --certificate <file>    Server certificate file (required)\n";
    std::cout << "  --private-key <file>    Server private key file (required)\n";
    std::cout << "  -p <port>               Port to listen on (default: 4433)\n";
    std::cout << "  -v, -vv, -vvv, -vvvv    Set verbosity level (default: 0)\n";
    std::cout << "  -h, --help              Show this help message\n";
}

int main(int argc, char *argv[]) {
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context key;
    mbedtls_x509_crt cert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret;
    int verbosity = 0;
    std::string port = DEFAULT_PORT;
    std::string ca_cert_file;
    std::string server_cert_file;
    std::string server_key_file;

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
        } else if (arg == "--ca-certificate" && i + 1 < argc) {
            ca_cert_file = argv[++i];
        } else if (arg == "--certificate" && i + 1 < argc) {
            server_cert_file = argv[++i];
        } else if (arg == "--private-key" && i + 1 < argc) {
            server_key_file = argv[++i];
        } else {
            std::cerr << "Unexpected argument: " << arg << std::endl;
            print_help(binary_name);
            return 1;
        }
    }

    if (ca_cert_file.empty() || server_cert_file.empty() || server_key_file.empty()) {
        std::cerr << "Required argument missing.\n";
        print_help(binary_name);
        return 1;
    }

    initialize_mbedtls(ssl, ssl_conf, cacert, key, cert, ctr_drbg, entropy);

    // Initialize RNG
    std::cout << "Initializing seed CTR-DRBG ..." << std::endl;
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    handle_error(ret, "Failed to seed CTR-DRBG");

    std::cout << "Loading CA certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&cacert, ca_cert_file.c_str());
    handle_error(ret, "Failed to parse CA certificate");

    std::cout << "Loading server certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&cert, server_cert_file.c_str());
    handle_error(ret, "Failed to parse server certificate");

    std::cout << "Loading server private key..." << std::endl;
    ret = mbedtls_pk_parse_keyfile(&key, server_key_file.c_str(), NULL);
    handle_error(ret, "Failed to parse server private key");

    std::cout << "Setting up SSL configuration..." << std::endl;
    ret = mbedtls_ssl_config_defaults(&ssl_conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    handle_error(ret, "Failed to configure SSL");

    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_own_cert(&ssl_conf, &cert, &key);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);  // Set RNG

    // Set debug callback and verbosity level
    mbedtls_ssl_conf_dbg(&ssl_conf, debug_callback, &verbosity);
    mbedtls_debug_set_threshold(verbosity);

    std::cout << "Setting up SSL context..." << std::endl;
    ret = mbedtls_ssl_setup(&ssl, &ssl_conf);
    handle_error(ret, "Failed to set up SSL context");

    std::cout << "Binding to port..." << std::endl;
    mbedtls_net_init(&listen_fd);
    ret = mbedtls_net_bind(&listen_fd, NULL, port.c_str(), MBEDTLS_NET_PROTO_TCP);
    handle_error(ret, "Failed to bind to port");

    std::cout << "Server is running. Waiting for connections...\n";

    while (true) {
        mbedtls_net_init(&client_fd);
        ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
        if (ret != 0) {
            std::cerr << "Failed to accept connection. Error code: " << ret << std::endl;
            mbedtls_net_free(&client_fd);
            continue; // Continue to accept new connections
        }

        std::cout << "Client connected. Setting up SSL..." << std::endl;
        mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
        ret = mbedtls_ssl_handshake(&ssl);
        if (ret != 0) {
            std::cerr << "SSL handshake failed. Error code: " << ret << std::endl;
            std::string verify_result = get_ssl_verify_result(ssl);
            std::cout << verify_result << std::endl;
        } else {
            std::cout << "SSL handshake successful\n";
        }

        // Close the connection
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&client_fd);
        mbedtls_ssl_session_reset(&ssl);  // Reset SSL session for the next connection
    }

    // Cleanup resources
    mbedtls_net_free(&listen_fd);
    cleanup_mbedtls(ssl, ssl_conf, cacert, key, cert, ctr_drbg, entropy);

    return 0;
}
