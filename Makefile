# Compiler and linker
CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -O2
LDFLAGS ?= -lmbedcrypto -lmbedtls -lmbedx509

# Output binaries
SERVER_BIN = mbedtls_script_server
CLIENT_BIN = mbedtls_script_client

# Source files
SERVER_SRC = server.cpp
CLIENT_SRC = client.cpp

# Targets and rules
all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SERVER_SRC) $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(CLIENT_SRC) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)

# Phony targets
.PHONY: all clean
