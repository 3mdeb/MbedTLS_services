#include "common.h"
#include <fstream>
#include <vector>
#include <iostream>
#include <cstring>
#include <psa/crypto.h>
#include <mbedtls/pem.h>
#include <mbedtls/platform.h>

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
        std::cerr << msg << "Error Code: " << status << " -> " << get_psa_error_message(status) << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void print_help(const std::string& binary_name) {
    std::cout << "Usage: " << binary_name << " [command] [options]\n";
    std::cout << "Commands:\n";
    std::cout << "  store --key-id <id> --key-file <file>      Store a private key\n";
    std::cout << "  list                                       List all stored keys\n";
    std::cout << "  delete --key-id <id>                       Delete a specified key\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help                                 Show this help message\n";
}

void store_key(psa_key_id_t key_id, const std::string& key_file) {
    // Load the key from the file
    std::ifstream file(key_file, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        handle_error(-1, "Failed to open key file: " + key_file, 0, false);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read((char*)buffer.data(), size)) {
        handle_error(-1, "Failed to read key file: " + key_file, 0, false);
    }

    // Check if the key is PEM encoded
    if (buffer.size() > 0 && buffer[0] == '-') {
        mbedtls_pem_context pem;
        mbedtls_pem_init(&pem);

        size_t use_len;
        int ret = mbedtls_pem_read_buffer(&pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----",
                                          buffer.data(), NULL, 0, &use_len);
        if (ret != 0) {
            mbedtls_pem_free(&pem);
            handle_error(ret, "Failed to parse PEM key file: " + key_file, 0, false);
        }

        buffer.assign(pem.buf, pem.buf + pem.buflen);
        mbedtls_pem_free(&pem);
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_id(&attributes, key_id);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);

    psa_status_t status = psa_import_key(&attributes, buffer.data(), buffer.size(), &key_id);
    handle_psa_error(status, "Failed to import key. ");

    std::cout << "Key stored successfully with ID: " << key_id << std::endl;
}

void list_keys() {
    // Placeholder for key listing implementation
    // PSA Crypto API does not currently provide a direct way to list keys
    // You would need to manage key IDs separately in a secure manner
    std::cout << "Placeholder. Listing keys is not directly supported by PSA Crypto API." << std::endl;
}

void delete_key(psa_key_id_t key_id) {
    psa_status_t status = psa_destroy_key(key_id);
    handle_psa_error(status, "Failed to delete key. ");

    std::cout << "Key deleted successfully with ID: " << key_id << std::endl;
}

int main(int argc, char *argv[]) {
    // Initialize the PSA Crypto library
    psa_status_t status = psa_crypto_init();
    handle_psa_error(status, "Failed to initialize PSA Crypto library. ");

    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "store") {
        psa_key_id_t key_id = 0;
        std::string key_file;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--key-id" && i + 1 < argc) {
                key_id = std::stoi(argv[++i]);
            } else if (arg == "--key-file" && i + 1 < argc) {
                key_file = argv[++i];
            }
        }

        if (key_id == 0 || key_file.empty()) {
            print_help(argv[0]);
            return 1;
        }

        store_key(key_id, key_file);
    } else if (command == "list") {
        list_keys();
    } else if (command == "delete") {
        psa_key_id_t key_id = 0;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--key-id" && i + 1 < argc) {
                key_id = std::stoi(argv[++i]);
            }
        }

        if (key_id == 0) {
            print_help(argv[0]);
            return 1;
        }

        delete_key(key_id);
    } else {
        print_help(argv[0]);
        return 1;
    }

    return 0;
}
