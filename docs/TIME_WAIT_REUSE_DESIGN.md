# Design: Local Port Reuse and TIME_WAIT Handling

## 1. Objective
Enable efficient local port reuse, specifically targeting sockets in the `TIME_WAIT` state, to support high-throughput scenarios (e.g., rapid server restarts, massive outgoing connection churn). This involves implementing mechanisms similar to `SO_REUSEADDR`, `SO_REUSEPORT`, and `tcp_tw_reuse`.

## 2. Current Limitation
- **Unsafe Bind**: The current `TCPEndpoint.bind` implementation indiscriminately overwrites any existing endpoint in the `TransportTable` without checking for conflicts. This is non-compliant with POSIX and dangerous.
- **Hardcoded TIME_WAIT**: The `TIME_WAIT` state is hardcoded to 60 seconds (`src/transport/tcp.zig`), with no configuration option.
- **Missing Socket Options**: `SO_REUSEADDR` and `SO_REUSEPORT` are not implemented in `EndpointOption`.

## 3. Proposed Changes

### 3.1 Socket Options
Extend `EndpointOption` in `src/tcpip.zig` to include:
- `reuse_address: bool`: Equivalent to `SO_REUSEADDR`. Allows binding to a port in `TIME_WAIT`.
- `reuse_port: bool`: Equivalent to `SO_REUSEPORT`. Allows multiple sockets to bind to the same port (load balancing).

### 3.2 Safe Bind Logic
Modify `src/transport/tcp.zig`'s `bind` function (and potentially `src/stack.zig`) to:
1.  **Check Existence**: Before registering, query the `TransportTable` for an existing endpoint at the requested `(local_addr, local_port)`.
2.  **Conflict Resolution**:
    -   If **No Match**: Proceed to register.
    -   If **Match Found**:
        -   If match is in `TIME_WAIT` AND `new_socket.reuse_address` is true: **Allow Reuse** (Overwrite/Hijack).
            -   *Note*: For strict `tcp_tw_reuse` semantics (outgoing connections), we must also check TCP Timestamps (RFC 1323) to ensure safety against old packets.
        -   If `new_socket.reuse_port` is true AND `existing_socket.reuse_port` is true: **Allow Reuse** (Requires `TransportTable` to support multiple values per key or a "group" mechanism, potentially complex. Phase 1 might skip this).
        -   Otherwise: Return `Error.DuplicateAddress` (Address in use).

### 3.3 Stack Configuration (Tunables)
Introduce stack-level configuration options (passed during `Stack.init` or via a config struct) to mirror Linux kernel tunables:
-   `time_wait_duration`: Default 60s. allow reducing it (e.g., to 1s or ms for high-perf internal networks).
    -   *Linux equivalent*: `TCP_TIMEWAIT_LEN` (hardcoded 60s in Linux, usually), `net.ipv4.tcp_fin_timeout` (for FIN_WAIT_2).
-   `tcp_tw_reuse`: Global boolean to enable RFC 1323 timestamp-based reuse for outgoing connections.

## 4. Implementation Steps

### Step 1: Fix `TransportTable` Interface
Modify `src/stack.zig`:
-   Add `contains(id)` or usage of `get(id)` in `registerTransportEndpoint` to detect conflicts.
-   Return `Error.DuplicateAddress` if collision occurs.

### Step 2: Add Socket Options
Modify `src/tcpip.zig`:
-   Update `EndpointOptionType` enum.
-   Update `EndpointOption` union.

Modify `src/transport/tcp.zig`:
-   Add `reuse_addr` and `reuse_port` fields to `TCPEndpoint`.
-   Implement `setOption` support for these fields.

### Step 3: Implement Reuse Logic in Bind
Modify `TCPEndpoint.bind` in `src/transport/tcp.zig`:
-   Perform the lookup before registration.
-   Implement the logic:
    ```zig
    if (stack.getTransportEndpoint(id)) |existing| {
        if (existing.state == .time_wait && self.reuse_addr) {
            // Safe to reclaim
            stack.unregisterTransportEndpoint(id); // Remove old
        } else {
            return Error.DuplicateAddress;
        }
    }
    stack.registerTransportEndpoint(id, ...);
    ```

### Step 4: Verification
-   Create a test case `test_bind_conflict` to verify `DuplicateAddress` error.
-   Create a test case `test_reuse_time_wait` to verify `reuse_addr` works for `TIME_WAIT` sockets.

## 5. Linux Kernel Tunables Reference

| Tunable | Description | ustack Equivalent |
| :--- | :--- | :--- |
| `net.ipv4.tcp_tw_reuse` | Allow reusing TIME-WAIT sockets for new connections if timestamp is larger. | Implement `reuse_addr` check + Timestamp check. |
| `SO_REUSEADDR` | Socket option to bind to an address in TIME_WAIT. | `EndpointOption.reuse_address`. |
| `SO_REUSEPORT` | Allow multiple listeners on same port. | `EndpointOption.reuse_port` (Future Work). |
| `net.ipv4.ip_local_port_range` | Range of ephemeral ports. | `stack.ephemeral_port` logic (already present, verify range). |

## 6. Code Examples

### Setting Option (User Code)
```zig
var ep = try tcp_proto.newEndpoint(&s, ...);
try ep.setOption(.{ .reuse_address = true });
try ep.bind(addr);
```

### Stack Side (Pseudo-code)
```zig
// src/transport/tcp.zig

pub fn setOption(self: *TCPEndpoint, opt: tcpip.EndpointOption) tcpip.Error!void {
    switch (opt) {
        .reuse_address => |val| self.reuse_addr = val,
        .ts_enabled => |val| self.ts_enabled = val,
        // ...
    }
}

pub fn bind(self: *TCPEndpoint, addr: tcpip.FullAddress) tcpip.Error!void {
    // ... calculate id ...
    if (self.stack.endpoints.get(id)) |existing_ep| {
         // Cast to TCPEndpoint to check specific state/flags
         // NOTE: This requires safe casting or extending the TransportEndpoint interface
         if (existing_ep.canBeReused(self.reuse_addr)) {
             self.stack.endpoints.remove(id);
         } else {
             return tcpip.Error.DuplicateAddress;
         }
    }
    // ... register ...
}
```
