#include "common.h"

void print_help(const std::string& binary_name) {
    std::cout << "Usage: " << binary_name << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --ca-certificate <file> CA certificate file (required)\n";
    std::cout << "  --ca-server-addr <ip address> CA Server IP address\n";
    std::cout << "  --peer-addr <ip address> peer addres for mutual authentication\n";
    std::cout << "  -p <port>               Port to use for communication (default: 4433)\n";
    std::cout << "  -v, -vv, -vvv, -vvvv    Set verbosity level (default: 0)\n";
    std::cout << "  -h, --help              Show this help message\n";
}

static int write_csr_to_buffer(mbedtls_x509write_csr *write_csr,
		mbedtls_pk_context *key, unsigned char output_buf[CSR_SIZE],
		int (*f_rng)(void *, unsigned char *, size_t), void *p_rng){
    int ret = 0;

    std::cout << "Writing CSR..." << std::endl;

    mbedtls_x509write_csr_set_md_alg(write_csr, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_csr_set_subject_name(write_csr, "Test Subject");
    handle_error(ret, "Failed to set CSR subject name");

    ret = mbedtls_x509write_csr_set_key_usage(write_csr,
		    MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
		    MBEDTLS_X509_KU_NON_REPUDIATION |
		    MBEDTLS_X509_KU_KEY_ENCIPHERMENT |
		    MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
		    MBEDTLS_X509_KU_KEY_AGREEMENT |
		    MBEDTLS_X509_KU_KEY_CERT_SIGN |
		    MBEDTLS_X509_KU_CRL_SIGN);
    handle_error(ret, "Failed to set CSR key usage");

    ret = mbedtls_x509write_csr_set_ns_cert_type(write_csr,
		    MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);
    handle_error(ret, "Failed to set CSR key usage");

    ret = mbedtls_x509write_csr_set_subject_name(write_csr, "C=PL,L=test,OU=test,O=test,CN=test,EMAIL=test@test.com");
    handle_error(ret, "Failed to set subject name");

    mbedtls_x509write_csr_set_key(write_csr, key); 

    ret = mbedtls_x509write_csr_pem(write_csr, output_buf, CSR_SIZE, f_rng, p_rng);
    handle_error(ret, "Failed to write CSR to PEM.");

    return ret;
}

static int setup_ssl(mbedtls_ssl_context *ssl, mbedtls_ssl_config *ssl_config,
		int (*f_rng)(void *, unsigned char *, size_t),
		mbedtls_ctr_drbg_context *p_rng, int verbosity){
    int ret = 0;

    ret = mbedtls_ssl_config_defaults(ssl_config,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    handle_error(ret, "Failed to configure SSL.");

    mbedtls_ssl_conf_authmode(ssl_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(ssl_config, f_rng, p_rng);

    // Set debug callback and verbosity level
    mbedtls_ssl_conf_dbg(ssl_config, debug_callback, &verbosity);
    mbedtls_debug_set_threshold(verbosity);

    std::cout << "Setting up SSL context..." << std::endl;
    ret = mbedtls_ssl_setup(ssl, ssl_config);
    handle_error(ret, "Failed to set up SSL context.");

    return ret;
}

static int do_handshake(mbedtls_ssl_context *ssl,
		mbedtls_net_context *fd){
    int ret = 0;

    std::cout << "Starting handshake..." << std::endl;
    mbedtls_ssl_set_bio(ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ret = mbedtls_ssl_handshake(ssl);
    if (ret != 0) {
        std::cerr << "Handshake failed. Error code: " << ret << std::endl;
        std::cerr << get_ssl_verify_result(*ssl) << std::endl;
    } else {
        std::cout << "Handshake successful!" << std::endl;
    }

    return ret;
}

static int send_csr(mbedtls_ssl_context *ssl, unsigned char csr_buf[CSR_SIZE]){
    int ret = 0;

    ret = mbedtls_ssl_write(ssl, csr_buf, CSR_SIZE);
    handle_error(ret, "Failed to send CSR.");

    return ret;
}

static int recieve_certificate(mbedtls_ssl_context *ssl, unsigned char cert_buf[CLIENT_CERT_SIZE]){
    int ret = 0;

    ret = mbedtls_ssl_read(ssl, cert_buf, CLIENT_CERT_SIZE);
    handle_error(ret, "Failed to recieve certificate");

    return ret;
}

int main(int argc, char *argv[]) {
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cert;
    mbedtls_rsa_context *rsa_ctx;
    mbedtls_pk_context key;
    std::string ca_cert_file;

    mbedtls_net_context listen_fd, peer_fd, ca_server_fd;
    mbedtls_ssl_context ssl_peer, ssl_ca_server;
    mbedtls_ssl_config ssl_conf_peer, ssl_conf_ca_server;
    std::string port = DEFAULT_PORT;
    std::string ca_server_addr;
    std::string peer_addr;

    mbedtls_x509write_csr write_csr;
    unsigned char csr_buf[CSR_SIZE];
    unsigned char cert_buf[CLIENT_CERT_SIZE];

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
        } else if (arg == "--ca-certificate" && i + 1 < argc) {
            ca_cert_file = argv[++i];
	} else if (arg == "--ca-server-addr" && i + 1 < argc){
            ca_server_addr = argv[++i];
	} else if (arg == "--peer-addr" && i + 1 < argc){
            peer_addr = argv[++i];
        } else {
            std::cerr << "Unexpected argument: " << arg << std::endl;
            print_help(binary_name);
            return 1;
        }
    }

    if (ca_cert_file.empty()) {
        std::cerr << "Required argument missing.\n";
        print_help(binary_name);
        return 1;
    }

    // Init SSL for communication with CA server:
    mbedtls_x509write_csr_init(&write_csr);
    mbedtls_ssl_init(&ssl_ca_server);
    mbedtls_ssl_config_init(&ssl_conf_ca_server);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_pk_init(&key);
    mbedtls_x509_crt_init(&cert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Initialize RNG
    std::cout << "Initializing seed CTR-DRBG ..." << std::endl;
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL,
		    0);
    handle_error(ret, "Failed to seed CTR-DRBG");

    std::cout << "Loading CA certificate..." << std::endl;
    ret = mbedtls_x509_crt_parse_file(&cacert, ca_cert_file.c_str());
    handle_error(ret, "Failed to parse CA certificate");

    std::cout << "Generating server private key..." << std::endl;

    // PK should have type MBETLS_PK_RSA to continue:
    switch (mbedtls_pk_get_type(&key)){
        case MBEDTLS_PK_RSA:
	    break;
	default:
	    handle_error(1, "PK context is not of type MBETLS_PK_RSA");
    }

    // Extract key handler to generate and save RSA key:
    rsa_ctx = mbedtls_pk_rsa(key);
    if (rsa_ctx == NULL)
        handle_error(1, "Failed to get RSA context");

    // Generate the keys:
    ret = mbedtls_rsa_gen_key(rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, PUBLIC_EXPONENT);
    handle_error(ret, "Failed to generate server private key");

    // Prepare CSR for sending to TA, the final CSR is being written to the
    // buffer in PEM format:
    std::cout << "Acquiring certificate..." << std::endl;
    ret = write_csr_to_buffer(&write_csr, &key, csr_buf,
		mbedtls_ctr_drbg_random, &ctr_drbg);
    handle_error(ret, "Failed to write CSR to buffer");

    // Setup SSL for communications with CA:
    ret = setup_ssl(&ssl_ca_server, &ssl_conf_ca_server,
		    mbedtls_ctr_drbg_random, &ctr_drbg, verbosity);
    handle_error(ret, "Failed to set up SLL server");

    std::cout << "Connecting via SSL..." << std::endl;
    mbedtls_net_init(&ca_server_fd);
    ret = mbedtls_net_connect(&ca_server_fd, ca_server_addr.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP);
    handle_error(ret, "Failed to connect via SSL.");

    // Handshake but without certificates:
    ret = do_handshake(&ssl_ca_server, &ca_server_fd);
    handle_error(ret, "Failed to do a handshake with CA server");

    ret = send_csr(&ssl_ca_server, csr_buf);
    handle_error(ret, "Failed to send CSR");

    ret = recieve_certificate(&ssl_ca_server, cert_buf);
    handle_error(ret, "Failed to get server certificate from CA");

    ret = mbedtls_x509_crt_parse_der(&cert, cert_buf, CLIENT_CERT_SIZE);
    handle_error(ret, "Failed to parse issued certificate");

    // Initialize SLL for communication with peer:
    mbedtls_ssl_init(&ssl_peer);
    mbedtls_ssl_config_init(&ssl_conf_peer);

    // Setup SSL for communications with peer:
    ret = setup_ssl(&ssl_peer, &ssl_conf_peer,
		    mbedtls_ctr_drbg_random, &ctr_drbg, verbosity);

    std::cout << "Binding to port..." << std::endl;
    mbedtls_net_init(&listen_fd);
    ret = mbedtls_net_bind(&listen_fd, NULL, port.c_str(), MBEDTLS_NET_PROTO_TCP);
    handle_error(ret, "Failed to bind to port");

    while (true) {
        mbedtls_net_init(&peer_fd);
        ret = mbedtls_net_accept(&listen_fd, &peer_fd, NULL, 0, NULL);
        if (ret != 0) {
            std::cerr << "Failed to accept connection. Error code: " << ret
		    << std::endl;
            mbedtls_net_free(&peer_fd);
            continue; // Continue to accept new connections
        }

        std::cout << "Client connected. Setting up SSL..." << std::endl;
        mbedtls_ssl_set_bio(&ssl_peer, &peer_fd, mbedtls_net_send,
			mbedtls_net_recv, NULL);
        ret = mbedtls_ssl_handshake(&ssl_peer);
        if (ret != 0) {
            std::cerr << "SSL handshake failed. Error code: " << ret
		    << std::endl;
            std::string verify_result = get_ssl_verify_result(ssl_peer);
            std::cout << verify_result << std::endl;
        } else {
            std::cout << "SSL handshake successful\n";
        }

        // Close the connection
        mbedtls_ssl_close_notify(&ssl_peer);
        mbedtls_net_free(&peer_fd);
        mbedtls_ssl_session_reset(&ssl_peer);  // Reset SSL session for the next connection
    }

    // Cleanup resources
    mbedtls_net_free(&listen_fd);

    mbedtls_ssl_free(&ssl_ca_server);
    mbedtls_ssl_config_free(&ssl_conf_ca_server);
    mbedtls_ssl_free(&ssl_peer);
    mbedtls_ssl_config_free(&ssl_conf_peer);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&key);
    mbedtls_x509_crt_free(&cert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
