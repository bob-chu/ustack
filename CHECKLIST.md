# Pre-Commit Checklist

## Fixes Implemented
- [x] **TCP Logic Fixes**:
    - [x] Queued initial `SYN` packet for retransmission in `connect`.
    - [x] Initialized `snd_nxt` with a randomized value for security and standard compliance.
    - [x] Updated `syn_sent` handler to correctly parse options, transition to `established`, and clear the retransmission queue/timer.
    - [x] Updated `established` handler to always process ACK flags (fix flow control/dup ACKs).
    - [x] Implemented retransmission timeout handling (max 30 retries) to prevent indefinite hanging.
- [x] **Driver Fixes**:
    - [x] Corrected `tap.zig` to parse Ethernet headers instead of stripping them prematurely.
    - [x] Fixed `eth.zig` writing logic (removed debug prints).
- [x] **ARP/Route Integration**:
    - [x] Handled `WouldBlock` in `Route.writePacket` when ARP is missing.
    - [x] Added application-level retry mechanism in `example_tap_libev_mux` for ARP resolution delays.
- [x] **Stack Core**:
    - [x] Fixed `Stack.findRoute` usage and error propagation.
    - [x] Removed unused `ShardCount` reference in `unregisterTransportEndpoint`.

## Verification
- [x] `example_tap_libev_mux` runs successfully against `www.google.com`.
- [x] TCP 3-way handshake completes (SYN -> SYN-ACK -> ACK).
- [x] Data transfer works (HTTP GET request -> Response).
- [x] Proper termination on EOF or error.

## Notes for Reviewer
- The `example_tap_libev_mux` requires `CAP_NET_ADMIN` (or Docker privilege) to create the TAP interface.
- Debug prints have been largely cleaned up, but some `std.debug.print` calls remain in error paths for visibility.
