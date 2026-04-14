.PHONY: run run-forward query test check

# Default values
RESOLVER ?= 8.8.8.8:53
DOMAIN ?= google.com

run:
	@echo "🌈 Starting IrisDNS Server..."
	cargo run

run-forward:
	@echo "🌈 Starting IrisDNS Server (Forwarding to $(RESOLVER))..."
	cargo run -- --resolver $(RESOLVER)

query:
	@echo "🔍 Querying IrisDNS for $(DOMAIN)..."
	cargo run --bin iris-cli -- $(DOMAIN)

query-upstream:
	@echo "🔍 Querying $(RESOLVER) directly for $(DOMAIN)..."
	cargo run --bin iris-cli -- -s $(RESOLVER) $(DOMAIN)

test:
	@echo "🧪 Running Test Suite..."
	cargo test

check:
	@echo "✅ Running Cargo Check..."
	cargo check

clean:
	@echo "🧹 Cleaning cargo build..."
	cargo clean
