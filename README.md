# 🌈 IrisDNS

**IrisDNS** is a high-performance, modular DNS recursive forwarder and parser built in Rust. Named after the personification of the rainbow and messenger of the gods, Iris acts as the bridge between your local network and the global internet.

## ✨ Features

- **🚀 High Performance**: Zero-copy parsing using Rust's lifetime system (`&'a [u8]`) for maximum efficiency.
- **🛡️ Battle-Hardened**: Robust recursive name decompression with built-in protection against infinite jump loops.
- **🧩 Modular Architecture**: Cleanly segregated components for parsing, forwarding, and packet coordination.
- **🔍 Built-in CLI**: Includes `iris-cli`, a standalone testing tool to verify DNS resolutions.
- **🛡️ Memory Safe**: 100% Safe Rust with strict boundary checking on all buffer operations.

## 🏗️ Architecture

IrisDNS is structured into several focused modules:

*   **`protocol`**: A core library implementing the DNS specification (RFC 1035).
*   **`server`**: The core UDP engine and request coordinator.
*   **`forwarder`**: Handles the logic of splitting multi-question queries and merging upstream responses.
*   **`handler`**: Local resolution falls back here when no upstream is specified.

## 🚀 Quick Start

Ensure you have [Rust](https://rustup.rs/) installed.

### 1. Start the Server
Run the Iris server with an upstream resolver (e.g., Google's 8.8.8.8). The port defaults to **53** if omitted:
```bash
# Specifying a port
make run-forward RESOLVER=8.8.8.8:53

# Using the default port (53)
make run-forward RESOLVER=8.8.8.8
```

### 2. Query the Server
Open a new terminal and use the `iris-cli` to perform a lookup:
```bash
make query DOMAIN=openai.com
```

## 🛠️ Development

We use a simple `Makefile` for common development tasks:

| Command | Description |
| :--- | :--- |
| `make build` | Build the server and CLI binaries |
| `make test` | Run the full test suite |
| `make query` | Fast query using existing CLI binary (no build check) |
| `make query-dev` | Query while automatically checking for code changes |
| `make run` | Build and run server in standalone mode |
| `make clean` | Remove cargo artifacts |

## 🧪 Testing

IrisDNS is backed by a comprehensive unit test suite:
```bash
make test
```

## ⚖️ License
This project is licensed under the MIT License.
