.PHONY: build test check clean run-dev query-dev install

# Default values for development
RESOLVER ?= 8.8.8.8
DOMAIN ?= google.com

# Binaries
IRIS_BIN = ./target/debug/iris

build:
	@echo "🔨 Building IrisDNS (Debug)..."
	cargo build

install:
	@echo "🚀 Installing IrisDNS globally..."
	cargo install --path .

test:
	@echo "🧪 Running Test Suite..."
	cargo test

check:
	@echo "✅ Running Cargo Check..."
	cargo check

run-dev:
	@echo "🌈 Starting IrisDNS Server (Dev Mode, Upstream: $(RESOLVER))..."
	cargo run -- start --resolver $(RESOLVER)

query-dev:
	@echo "🔍 Querying IrisDNS (Dev Mode, Domain: $(DOMAIN))..."
	cargo run -- query $(DOMAIN)

clean:
	@echo "🧹 Cleaning cargo build..."
	cargo clean
