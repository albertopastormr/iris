.PHONY: run run-forward query query-dev query-upstream build test check clean

# Default values
RESOLVER ?= 8.8.8.8:53
DOMAIN ?= google.com

# Binaries
SERVER_BIN = ./target/debug/iris
CLI_BIN = ./target/debug/iris-cli

build:
	@echo "🔨 Building IrisDNS..."
	cargo build

run: build
	@echo "🌈 Starting IrisDNS Server..."
	$(SERVER_BIN)

run-forward: build
	@echo "🌈 Starting IrisDNS Server (Forwarding to $(RESOLVER))..."
	$(SERVER_BIN) --resolver $(RESOLVER)

query:
	@echo "🔍 Querying IrisDNS for $(DOMAIN)..."
	@if [ ! -f $(CLI_BIN) ]; then cargo build --bin iris-cli; fi
	$(CLI_BIN) $(DOMAIN)

query-dev:
	@echo "🔍 Querying IrisDNS for $(DOMAIN) (with build check)..."
	cargo run --bin iris-cli -- $(DOMAIN)

query-upstream:
	@echo "🔍 Querying $(RESOLVER) directly for $(DOMAIN)..."
	@if [ ! -f $(CLI_BIN) ]; then cargo build --bin iris-cli; fi
	$(CLI_BIN) -s $(RESOLVER) $(DOMAIN)

test:
	@echo "🧪 Running Test Suite..."
	cargo test

check:
	@echo "✅ Running Cargo Check..."
	cargo check

clean:
	@echo "🧹 Cleaning cargo build..."
	cargo clean
