# Agent Guidelines: ustack

This repository contains a high-performance, user-space TCP/IP network stack implemented in Zig (0.13.0). It is architecturally inspired by gVisor's netstack but optimized for Zig's memory management and concurrency models.

## 🛠 Build, Lint, and Test Commands

The project uses the standard Zig toolchain. A local Zig 0.13.0 distribution is available in the repository.

### 🐳 Docker Integration
For a consistent build and test environment, you can use Docker. 
**You must ensure the Docker container `my-ubuntu` is running before executing commands.**

```bash
# Start the container if it's not already running, better to ask user to start the docker container and
# let it running on other terminal 
# docker start my-ubuntu, example:
# docker run --rm -it --privileged --name my-ubuntu -p 8080:8080 -v .:/app -v ./../dpdk:/app/dpdk -v ../ustack/ustack:/ustack my_u24

# Run build/test commands via docker exec
docker exec my-ubuntu zig build
docker exec my-ubuntu zig build test
```

### 🏃 Running AF_PACKET Example (Server/Client)
To run the `AF_PACKET` example using a `veth` pair:

1. **Setup veth pair** (requires root/privileged):
   ```bash
   docker exec --privileged my-ubuntu /ustack/setup_veth.sh
   ```

2. **Start Server** (on `veth0`):
   ```bash
   docker exec --privileged -w /ustack my-ubuntu ./zig-out/bin/example_af_packet_libev veth0 server 10.0.0.2/24
   ```

3. **Start Client** (on `veth1`):
   ```bash
   docker exec --privileged -w /ustack my-ubuntu ./zig-out/bin/example_af_packet_libev veth1 client 10.0.0.1/24 10.0.0.2
   ```

### 🏗 Building
- **Build library (static/shared):** `zig build` (artifacts in `zig-out/lib/`)
- **Build examples:** `zig build example` (artifacts in `zig-out/bin/`)

### 🧹 Linting & Formatting
- **Check formatting:** `zig fmt --check .`
- **Apply formatting:** `zig fmt .`
- **Zig Compiler:** Running any build or test command will perform semantic analysis and surface errors/warnings.

### 🧪 Testing
- **Run all tests:** `zig build test` or `zig test src/main.zig`
- **Run a single file's tests:** `zig test src/path/to/file.zig`
- **Run specific test case:** `zig test src/main.zig --test-filter "filter_string"`
- **Testing pattern:** Tests are typically at the bottom of the source file or aggregated in `src/main.zig` via `refAllDecls`.
- **Timeout Constrain:** All test runs must have a timeout constraint (e.g., using the `timeout` command or tool-specific timeout flags) to prevent hanging.

---

## 📏 Code Style Guidelines

### 1. Language & Toolchain
- **Zig Version:** 0.13.0 (strictly adhered to).
- **Format:** Always use `zig fmt`. Never use tabs; use 4 spaces for indentation.

### 2. Naming Conventions
- **Types (Structs, Enums, Unions):** `PascalCase` (e.g., `TCPEndpoint`, `NetworkProtocol`, `LinkAddress`).
- **Functions & Methods:** `camelCase` (e.g., `writePacket`, `newEndpoint`, `handlePacket`).
- **Variables & Struct Fields:** `snake_case` (e.g., `local_addr`, `snd_nxt`, `rcv_wnd`).
- **Constants:** `PascalCase` or `UPPER_SNAKE_CASE` depending on context (e.g., `CapabilityLoopback`, `IFF_TAP`, `ProtocolNumber`).

### 3. Imports
- **Internal Modules:** Use relative paths (e.g., `const tcpip = @import("../tcpip.zig");`).
- **Standard Library:** `const std = @import("std");`.
- **Package Alias:** In examples or external tests, use `@import("ustack")`.

### 4. Memory Management
- **Explicit Allocators:** Pass `std.mem.Allocator` to `init` functions. Avoid global allocators.
- **Cleanup:** Use `errdefer` for resource cleanup in functions that can return errors.
- **Reference Counting:** Some core objects (like `TransportEndpoint`) use manual reference counting (`incRef`/`decRef`).

### 5. Error Handling
- **Custom Error Set:** Use `tcpip.Error` for networking-related errors (e.g., `WouldBlock`, `NoRoute`, `UnknownProtocol`).
- **Propagation:** Use `try` for propagation. Avoid ignoring errors with empty `catch` blocks.
- **Exhaustive Switches:** Use Zig's exhaustive switching on error sets and enums.

### 6. Architectural Patterns
- **Interfaces (VTables):** Polymorphism is achieved via structs containing a `ptr: *anyopaque` and a pointer to a `VTable`. See `stack.zig` for `LinkEndpoint`, `NetworkEndpoint`, and `TransportProtocol`.
- **Concurrency (Sharding):** The transport table is sharded (256 shards) to minimize lock contention. Use shard-level locking where appropriate.
- **Zero-Copy Buffers:** Use `buffer.VectorisedView` (scatter-gather) and `buffer.Prependable` (backwards-growing header buffer) for packet data. Avoid unnecessary memory copies.
- **Wait Queues:** Use `waiter.Queue` for blocking/non-blocking I/O notification logic, similar to Linux wait queues.

### 7. Project Structure
- `src/network/`: IPv4, IPv6, ARP, ICMP implementation.
- `src/transport/`: TCP (state machine), UDP, and congestion control algorithms (CUBIC, BBR).
- `src/link/`: Ethernet and link-layer abstractions.
- `src/drivers/`: OS-specific adapters (Linux TAP, AF_PACKET, AF_XDP).
- `src/buffer.zig`: Core zero-copy buffer abstractions.

---

---

## ✅ Success Criteria & Requirements
- **Test Coverage:** Every new piece of code must be accompanied by relevant unit tests.
- **Regression Testing:** All changes must pass the existing unit test suite.
- **Integration Testing:** All changes must pass all examples (`zig build example`) and any `test*` files in the root directory.
- **Zero Warnings:** Code should compile without warnings or semantic errors.

## 🚫 Prohibited Patterns
- **No Automatic Git Operations:** NEVER perform git operations (add, commit, push, etc.) without explicit user approval for each step.
- **No Refactoring during Bugfixes:** Keep fixes minimal and focused. Do not refactor unrelated code.
- **No Unsafe Pointers:** Avoid `*anyopaque` casting unless implementing or using an interface pattern.
- **No Magic Numbers:** Use constants defined in `header.zig` or `tcpip.zig`.
- **No Suppressing Errors:** Never use `_ = someFunction();` if it returns an error that should be handled.
