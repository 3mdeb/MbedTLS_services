# Compiler and linker
CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -O2
LDFLAGS ?= -lmbedcrypto -lmbedtls -lmbedx509

# Output binaries
SERVER_BIN = mbedtls_script_server
CLIENT_BIN = mbedtls_script_client
UTIL_BIN = psa_util
CA_BIN = mbedtls_script_ca
PEER_BIN = mbedtls_script_peer

# Source files
SERVER_SRC = server.cpp
CLIENT_SRC = client.cpp
UTIL_SRC = psa_util.cpp
COMMON_SRC = common.cpp
CA_SRC = ca.cpp
PEER_SRC = peer.cpp

# Targets and rules
all: $(SERVER_BIN) $(CLIENT_BIN) $(UTIL_BIN) $(CA_BIN) $(PEER_BIN)

$(SERVER_BIN): $(SERVER_SRC) $(COMMON_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SERVER_SRC) $(COMMON_SRC) $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC) $(COMMON_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(CLIENT_SRC) $(COMMON_SRC) $(LDFLAGS)

$(UTIL_BIN): $(UTIL_SRC) $(COMMON_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(UTIL_SRC) $(COMMON_SRC) $(LDFLAGS)

$(CA_BIN): $(CA_SRC) $(COMMON_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(CA_SRC) $(COMMON_SRC) $(LDFLAGS)

$(PEER_BIN): $(PEER_SRC) $(COMMON_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(PEER_SRC) $(COMMON_SRC) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN) $(UTIL_BIN) $(CA_BIN) $(PEER_BIN)

# Phony targets
.PHONY: all clean
