# Check-in List - ustack Benchmark Improvements

## Examples & Benchmarks
- **ping_pong.zig**: 
    - Silenced `Conn X: closing` logs to reduce overhead.
    - Added `-n <max_conns>` support for server-side graceful exit.
    - Improved reporting logic to ensure benchmark stats are printed even on errors.
    - Fixed `active_conns` leaks in client setup using `errdefer`.
    - Increased packet processing budget and timer resolution.
- **uperf.zig**:
    - Aligned timer resolution and MSL settings with benchmark requirements.

## Core Stack Improvements
- **TCP (transport/tcp.zig)**:
    - Implemented `TIME_WAIT` state with configurable MSL (default reduced for benchmarks).
    - Added pool prewarming for endpoints, nodes, and views to handle bursts.
    - Fixed connection unregistration and reference counting during close.
    - Optimized ACK handling (piggyback ACKs, delayed ACK timer).
- **Buffer Management (buffer.zig)**:
    - Added `prewarm` capability to pools for performance.
    - Optimized node acquisition and release.
- **Link Layer (af_packet.zig)**:
    - Optimized TX path to avoid ring buffer overhead in standard cases.
    - Increased RX/TX buffer sizes.
- **Network Layer (arp.zig)**:
    - Reduced ARP retry interval for faster resolution.
- **Performance (header.zig)**:
    - Optimized `internetChecksum` with loop unrolling.

## Bug Fixes & Stability
- Fixed memory leaks in `Stack.deinit` by properly decrementing endpoint references.
- Improved resource cleanup in `TCPEndpoint` (waiter queues, timers).
- Ensured consistent event notification across state transitions.
