# 🌈 IrisDNS

**IrisDNS** is a high-performance, modular DNS recursive forwarder and parser built in Rust. Named after the messenger of the gods, Iris bridges the gap between your local network and the global internet with speed and safety.

---

## 🚀 Getting Started

### 1. Installation
Install the Iris binary globally using Cargo:
```bash
cargo install --path .
```
Verify the installation:
```bash
iris --help
```

### 2. Start the Server
Launch the Iris server with an upstream resolver (like Google's 8.8.8.8):
```bash
# Starts the server on 127.0.0.1:2053
iris start --resolver 8.8.8.8
```

### 3. Query the Server
In a separate terminal, use the same binary to perform a lookup:
```bash
iris query openai.com
```

---

## 🏗️ Architecture

IrisDNS is built for performance and reliability:
- **🚀 Zero-Copy Parsing**: Leverages Rust's lifetime system for peak memory efficiency.
- **🛡️ Battle-Hardened**: Protection against recursive loops and malformed packets.
- **🧩 Modular**: Cleanly separated protocol, resolver, and server layers.

---

## 🛠️ Development

If you are contributing to IrisDNS, use the provided `Makefile` for common tasks:

| Command | Description |
| :--- | :--- |
| `make build` | Build the binary in debug mode |
| `make test` | Run the full test suite (unit + integration) |
| `make check` | Run static analysis (clippy) |
| `make query-dev` | Build and run a query in one step |
| `make run-dev` | Build and start the server with an upstream resolver |
| `make clean` | Remove all build artifacts |

### Running Tests
```bash
make test
```

### Direct Development Commands
You can also use `cargo run` directly to pass custom subcommands to the binary while developing:
```bash
cargo run -- start --resolver 1.1.1.1
```

---

## ⚖️ License
This project is licensed under the MIT License.
