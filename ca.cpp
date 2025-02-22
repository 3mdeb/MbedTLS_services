#include "common.h"

void print_help(const std::string& binary_name) {
    std::cout << "Usage: " << binary_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --ca-root-certificate <file> CA root certificate file (required)\n";
    std::cout << "  --ca-root-key <file>    CA private key file (required)\n";
    std::cout << "  --ca-server-certificate <file>  CA self-signed server certificate\n";
    std::cout << "  --ca-server-key <file>  CA server private key\n";
    std::cout << "  -p <port>               Port to listen on (default: 4433)\n";
    std::cout << "  -v, -vv, -vvv, -vvvv    Set verbosity level (default: 0)\n";
    std::cout << "  -h, --help              Show this help message\n";
}

// Function to generate a client certificate signed by the CA
int issue_client_certificate(mbedtls_pk_context *ca_key, mbedtls_x509_csr *csr,
		unsigned char cert_buf[CERT_SIZE],
		int (*f_rng)(void *, unsigned char *, size_t),
		mbedtls_ctr_drbg_context *ctr_drbg) {
    int ret = 0;
    mbedtls_x509write_cert cert; 

    // Initialize certificate context
    mbedtls_x509write_crt_init(&cert);

    mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);

    ret = mbedtls_x509write_crt_set_ns_cert_type(&cert, csr->ns_cert_type);
    handle_error(ret, "Failed to set certificate type");

    ret = mbedtls_x509write_crt_set_key_usage(&cert, csr->key_usage);
    handle_error(ret, "Failed to set certificate key usage");

    ret = mbedtls_x509write_crt_set_issuer_name(&cert, "CN=CA,O=mbed TLS,C=PL");
    handle_error(ret, "Failed to set certificate issuer");

    ret = mbedtls_x509write_crt_set_subject_name(&cert, "CN=Cert,O=mbed TLS,C=PL");
    handle_error(ret, "Failed to set certificate subject");

    mbedtls_x509write_crt_set_subject_key(&cert, &(csr->pk));

    unsigned char serial_number[16];
    ret = mbedtls_ctr_drbg_random(ctr_drbg, serial_number,
		    sizeof(serial_number));
    handle_error(ret, "Failed to generate serial number");

    ret = mbedtls_x509write_crt_set_serial_raw(&cert, serial_number,
		    sizeof(serial_number));
    handle_error(ret, "Failed to set certificate serial number");

    // Set validity period start (17.02.2026 00:00:00) and end (17.02.2025 00:00:00):
    ret = mbedtls_x509write_crt_set_validity(&cert, "20250217000000",
		    "20260217000000");
    handle_error(ret, "Failed to set certificate validity period");

    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_issuer_key(&cert, ca_key);

    ret = mbedtls_x509write_crt_der(&cert, cert_buf, (size_t)CERT_SIZE,
                              f_rng, ctr_drbg);
    handle_error(ret, "Failed to write client certificate");

    mbedtls_x509write_crt_free(&cert);

    return ret;
}

int receive_csr(mbedtls_ssl_context *ssl, unsigned char output_buf[CSR_SIZE]){
    int ret = 0;

    ret = mbedtls_ssl_read(ssl, output_buf, CSR_SIZE);
    return ret;
}

static int send_certificate_to_client(mbedtls_ssl_context *ssl,
		unsigned char cert_buf[CERT_SIZE]){
    int ret = 0;

    ret = mbedtls_ssl_write(ssl, cert_buf, (size_t)CERT_SIZE);

    return ret;
}

int main(int argc, char *argv[]) {
    // Keys and certificates:
    mbedtls_x509_crt root_cert;
    mbedtls_pk_context root_key;
    std::string root_cert_file;
    std::string root_key_file;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;
    std::string server_cert_file;
    std::string server_key_file;

    // SSL:
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_conf;
    std::string port = DEFAULT_LISTEN_PORT;

    mbedtls_x509_csr csr;
    unsigned char csr_buf[CSR_SIZE];
    unsigned char issued_cert_buf[CERT_SIZE];

    // Other:
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret;
    int verbosity = 0;

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
        } else if (arg == "--ca-root-certificate" && i + 1 < argc) {
            root_cert_file = argv[++i];
        } else if (arg == "--ca-root-key" && i + 1 < argc) {
            root_key_file = argv[++i];
        } else if (arg == "--ca-server-certificate" && i + 1 < argc) {
            server_cert_file = argv[++i];
        } else if (arg == "--ca-server-key" && i + 1 < argc) {
            server_key_file = argv[++i];
        } else {
            std::cerr << "Unexpected argument: " << arg << std::endl;
            print_help(binary_name);
            return 1;
        }
    }

    if (root_cert_file.empty() || root_key_file.empty()
		    || server_cert_file.empty() || server_key_file.empty()) {
        std::cerr << "Required argument missing.\n";
        print_help(binary_name);
        return 1;
    }

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&root_cert);
    mbedtls_pk_init(&root_key);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&server_key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Initialize RNG
    std::cout << "Initializing seed CTR-DRBG ..." << std::endl;
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL,
		    0);
    handle_error(ret, "Failed to seed CTR-DRBG");

    std::cout << "Loading root certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&root_cert, root_cert_file.c_str());
    handle_error(ret, "Failed to parse CA certificate");

    std::cout << "Loading root private key..." << std::endl;
    ret = mbedtls_pk_parse_keyfile(&root_key, root_key_file.c_str(), NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
    handle_error(ret, "Failed to parse root private key");

    std::cout << "Loading server certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&server_cert, server_cert_file.c_str());
    handle_error(ret, "Failed to parse server certificate");

    std::cout << "Loading server private key..." << std::endl;
    ret = mbedtls_pk_parse_keyfile(&server_key, server_key_file.c_str(), NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
    handle_error(ret, "Failed to parse server private key");


    std::cout << "Setting up SSL configuration..." << std::endl;
    ret = mbedtls_ssl_config_defaults(&ssl_conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    handle_error(ret, "Failed to configure SSL");

    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &root_cert, NULL);
    mbedtls_ssl_conf_own_cert(&ssl_conf, &server_cert, &server_key);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Set debug callback and verbosity level
    mbedtls_ssl_conf_dbg(&ssl_conf, debug_callback, &verbosity);
    mbedtls_debug_set_threshold(verbosity);

    std::cout << "Setting up SSL context..." << std::endl;
    ret = mbedtls_ssl_setup(&ssl, &ssl_conf);
    handle_error(ret, "Failed to set up SSL context");

    std::cout << "Binding to port..." << std::endl;
    mbedtls_net_init(&listen_fd);
    ret = mbedtls_net_bind(&listen_fd, NULL, port.c_str(),
		    MBEDTLS_NET_PROTO_TCP);
    handle_error(ret, "Failed to bind to port");

    std::cout << "Server is running. Waiting for connections...\n";

    while (true) {
        mbedtls_net_init(&client_fd);
        ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
        if (ret != 0) {
            std::cerr << "Failed to accept connection. Error code: " << ret
		    << std::endl;
            mbedtls_net_free(&client_fd);
            continue; // Continue to accept new connections
        }

        std::cout << "Client connected. Setting up SSL..." << std::endl;
        mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send,
			mbedtls_net_recv, NULL);
        ret = mbedtls_ssl_handshake(&ssl);
        if (ret != 0) {
            std::cerr << "SSL handshake failed. Error code: " << ret
		    << std::endl;
            std::string verify_result = get_ssl_verify_result(ssl);
            std::cout << verify_result << std::endl;

            mbedtls_ssl_close_notify(&ssl);
            mbedtls_net_free(&client_fd);
            mbedtls_ssl_session_reset(&ssl);

	    continue;
        } else {
            std::cout << "SSL handshake successful\n";
        }

	std::cout << "Reading client CSR...\n";
	ret = receive_csr(&ssl, csr_buf);
	handle_error(ret, "Failed to read client CSR.", CSR_SIZE);

	std::cout << "Parsing client CSR...\n";
        ret = mbedtls_x509_csr_parse(&csr, csr_buf, (size_t)CSR_SIZE);
	handle_error(ret, "Could not parse client CSR");

	ret = issue_client_certificate(&root_key, &csr,
		issued_cert_buf, mbedtls_ctr_drbg_random, &ctr_drbg);
	handle_error(ret, "Failed to issue client certificate");

	ret = send_certificate_to_client(&ssl, issued_cert_buf);
	handle_error(ret, "Failed to send client certificate", CERT_SIZE);

        // Close the connection
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&client_fd);
        mbedtls_ssl_session_reset(&ssl);  // Reset SSL session for the next connection
    }

    // Cleanup resources
    mbedtls_net_free(&listen_fd);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_x509_crt_free(&root_cert);
    mbedtls_pk_free(&root_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
