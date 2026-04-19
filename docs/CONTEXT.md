# 🌈 IrisDNS: Technical Context for Next Agents

Welcome, Agent. You are entering the **IrisDNS** codebase—a high-performance, modular DNS recursive forwarder and parser built in idiomatic Rust.

---

## 🏗️ 1. High-Level Architecture
IrisDNS is structured as a **Crate Library (`lib.rs`)** that powers two binaries:

1.  **`src/main.rs`**: The primary DNS server.
2.  **`src/bin/iris-cli.rs`**: A standalone testing utility for resolution.

### Core Modules
*   **`protocol/`**: The "Spec-In-Code".
    *   `buffer.rs`: Zero-copy `PacketBuffer<'a>` with bounds-checking.
    *   `names.rs`: Recursive label decompression with `MAX_JUMPS`.
    *   `header.rs`, `question.rs`, `record.rs`, `message.rs`: Binary codecs.
*   **`server.rs`**: The main UDP listener and coordinator.
*   **`forwarder.rs`**: Business logic for splitting multi-question queries and merging responses from an upstream resolver.
*   **`handler.rs`**: Local resolution fallback.

---

## 🛡️ 2. Core Protocol Logic (The "How It Works")

### Robust Parsing
Inherently unstable upstream responses are handled gracefully:
- **`DnsRecord` Robustness**: Both `DnsQuestion` and `DnsRecord` use raw `u16` for type codes to allow forwarding specialized queries (like `AAAA` or `MX`) even if the server doesn't have specific parsing logic for them yet.
- **Support for CNAME**: Full recursive parsing of CNAME records is supported.
- **Fail-Safe RData**: Any unrecognized record types are stored as `RData::Unknown(Vec<u8>)` rather than failing the whole packet, ensuring the server stays up even when encountering modern DNS extensions.

### Zero-Copy Parsing
We use `PacketBuffer<'a>` to read from the UDP stream without initial heap allocation. It maintains a cursor (`pos`) and a lifetime link to the incoming byte slice, ensuring peak memory efficiency.

### Recursive Decompression
DNS names use pointers (`0xC0 [offset]`) for compression. Our `decode_name_recursive` logic handles these jumps up to `MAX_JUMPS = 5` to prevent infinite loop or "Zip Bomb" style attacks.

### The `ByteCodec` Trait
All protocol units implement a uniform trait:
```rust
pub trait ByteCodec: Sized {
    fn from_bytes(buffer: &mut PacketBuffer) -> Result<Self, DnsError>;
    fn to_bytes(&self, buf: &mut BytesMut);
}
```

---

## 🔄 3. Forwarding & Networking Flow

### Upstream Splitting
Many upstream resolvers (like 8.8.8.8) only handle **single-question** packets. IrisDNS implements **Packet Splitting**:
1.  Receive query with N questions.
2.  Spawn N separate upstream queries.
3.  Collect and merge N responses into a single client reply.
4.  ID mimicking: The response **must** match the original query ID.

### Flexible Upstream Addressing
The server supports both `IP:PORT` format and plain `IP` format (defaulting to port 53) for the upstream resolver configuration in `src/main.rs`.

---

## 🚧 4. Known Constraints & Future Directions

### Current Limits
-   **UDP/53 Primary**: No TCP support currently.
-   **512-Byte Bound**: Strict adherence to RFC 1035 packet limits.
-   **Blocking I/O**: The server uses a standard `std::net::UdpSocket` loop.

### Priority Level 2 Roadmap
1.  **Async Conversion**: Migrate to `tokio` for massive concurrent handling.
2.  **TTL-Aware Caching**: Prevent redundant upstream calls.
3.  **Ad-Blocking**: Add a local filter layer in `server.rs`.
4.  **DNS-over-HTTPS (DoH)**: Encrypted upstream forwarding.

---

## 🧪 5. Verification
A 16-test suite covers protocol edge cases, including:
-   Malformed `A` records lengths.
-   Boundary-checked u32/u16 reads.
-   Deeply nested name decompression.

Run tests using: `make test` or `cargo test`.

---

> **Final Note:** Every byte matters in IrisDNS. Maintain the zero-copy philosophy and stick to Rust’s safety guidelines. Good luck. 🚀🌈
