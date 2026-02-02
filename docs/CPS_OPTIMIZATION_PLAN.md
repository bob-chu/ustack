# Implementation Plan: 100k CPS TCP Optimization

---
**Document Version:** v1.0  
**Last Updated:** February 2, 2026  
**Status:** 🏗️ IN PROGRESS  
**Author:** Sisyphus (AI Agent)  
**Goal:** Achieve 100,000 Connections Per Second (CPS) with stable sub-10µs latency.

---

## Status Dashboard

| Phase | Status | Blocking Issues | Est. Completion |
|-------|--------|----------------|-----------------|
| **1.1** Implementation | ✅ COMPLETE | Fixed `@ctz` and `nextExpiration()` | - |
| **1.2** Verification | ✅ COMPLETE | Unit tests passed | - |
| **2.1** Stack Refactor | ✅ COMPLETE | Integrated into Stack | - |
| **2.2** Safety Hardening | ✅ COMPLETE | Fixed refcounting and close() bugs | - |
| **3.1** Pooling | ⚠️ CAN START | Next priority | - |
| **3.2** Sharding | ✅ COMPLETE | 256-shard TransportTable implemented | - |
| **3.3** Lazy Allocation | ❌ NOT STARTED | Low priority | - |
| **4** Validation | ❌ NOT STARTED | Depends on ALL phases | - |

**Legend:**  
- 🔧 BLOCKED: Cannot proceed due to active issues  
- ❌ NOT STARTED: Waiting on dependencies or not yet begun  
- ⚠️ CAN START: Ready to begin (no blockers)  
- 🏗️ IN PROGRESS: Actively being worked on  
- ✅ COMPLETE: Finished and verified

---

## Dependency Graph

```
Phase 1 (TimerWheel V2)
   ├─ 1.1 Implementation 🔧 BLOCKED
   └─ 1.2 Verification ❌ NOT STARTED
        ↓
Phase 2 (Integration)
   ├─ 2.1 Stack Refactor ❌ NOT STARTED
   └─ 2.2 Safety Hardening ❌ NOT STARTED
        ↓
Phase 4 (Validation) ❌ NOT STARTED

Phase 3 (Scalability) ⚠️ CAN START NOW (parallel track)
   ├─ 3.1 TCPEndpoint Pooling
   ├─ 3.2 Transport Table Sharding  
   └─ 3.3 Lazy Allocation
        ↓
Phase 4 (Validation)
```

**Critical Path:** Phase 1 → Phase 2 → Phase 4  
**Parallel Track:** Phase 3 can start immediately and run concurrently

**Key Insight:** Phase 3 (Pooling & Sharding) does NOT depend on Phase 1 (TimerWheel). These can be implemented in parallel to accelerate delivery.

---

## Resource Planning

| Phase | Estimated Effort | Dependencies | Risk Level | Notes |
|-------|-----------------|--------------|------------|-------|
| **1.1** | 2 days | None | Low | Isolated module, well-defined scope |
| **1.2** | 1 day | Phase 1.1 | Low | Unit tests, automated verification |
| **2.1** | 3 days | Phase 1.1, 1.2 | **High** | Integration risk, requires careful testing |
| **2.2** | 2 days | Phase 2.1 | Medium | Audit all endpoint lifecycle paths |
| **3.1** | 4 days | None | Medium | Memory management complexity |
| **3.2** | 3 days | None | Low | Refactoring, well-understood pattern |
| **3.3** | 2 days | None | Low | Conditional allocation logic |
| **4** | 5 days | All phases | **High** | Requires dedicated infrastructure, profiling |

**Total Estimated Duration:**  
- **Sequential (worst case):** 22 days  
- **Parallel (optimistic):** 14 days (Phase 1+2 in parallel with Phase 3)

**Skill Requirements:**  
- Systems programming (Zig, memory management)  
- TCP/IP protocol expertise  
- Performance profiling (`perf`, benchmarking)

---

## Phase 1: Bitmask-Optimized Timer Wheel (V2)
*Target: Eliminate $O(N)$ scheduling bottlenecks.*

### 1.1 Implementation (`src/time.zig`)
- **Structure**: Replace sorted linked list with 4 levels of 256 slots each.
- **Optimization**: Add `[4]u64` bitmasks per level for $O(1)$ next-timer search via `std.math.countTrailingZeros`.
- **Bulk Advance**: Implement `tickTo(target_tick)` to skip empty slots and prevent "timer storms" during high packet bursts.
- **Zero-Delay**: Handle `delay_ms = 0` by placing timers in the current processing slot.

### 1.2 Verification
- Run `zig test src/time.zig` covering:
    - Cascading across all 4 levels.
    - $O(1)$ next-timer lookup via bitmasks.
    - Timer wraparound logic.

---

## Phase 2: Core Stack Integration
*Target: Seamless transition and memory safety.*

### 2.1 Stack Refactor (`src/stack.zig`)
- Switch `Stack.timer_queue` from $O(N)$ list to the new `TimerWheel`.
- Update `Stack.init()` to pre-warm wheel structures if necessary.

### 2.2 Safety Hardening (`src/transport/tcp.zig`)
- Audit `TCPEndpoint.deinit()` to ensure all 3 timers (Retransmit, Keep-alive, Time-wait) are explicitly canceled.
- **Critical**: Prevent use-after-free by ensuring no timer callbacks can fire after an endpoint is pooled or destroyed.

---

## Phase 3: High-CPS Scalability Boosts
*Target: Minimize allocator pressure and hash collisions.*

### 3.1 TCPEndpoint Pooling
- Add a pre-allocated `buffer.Pool(TCPEndpoint)` to `TCPProtocol`.
- Refactor `accept()` to acquire from pool instead of heap allocation.

### 3.2 Transport Table Sharding
- Split the global `TransportTable` into **256 shards** (buckets).
- Selection logic: `hash(TransportEndpointID) % 256`.
- **Benefit (single-threaded):** Reduces hash collision chain lengths and improves CPU cache hit rate for 100k+ connections. Shorter chains mean faster connection lookups during packet processing.

**Note:** Sharding is NOT for multi-threading (ustack is single-threaded). It's a hash table optimization to reduce average lookup time from O(N/buckets) to O(N/256).

### 3.3 Lazy Allocation
- Defer SACK list and Congestion Control state allocation until the `ESTABLISHED` state is reached.
- Remove `SyncacheMap` from non-listening endpoints to save ~1KB per connection.

---

## Phase 4: Validation & Benchmarking
*Target: Quantifiable proof of 100k CPS performance.*

### 4.1 Latency Analysis
- **Metric:** P99 handshake latency (SYN → ESTABLISHED state transition)
- **Baseline:** 180µs @ 80k CPS (current master, 8-core Xeon E5-2670)
- **Target:** <50µs @ 100k CPS (same hardware)
- **Measurement Window:** 10-minute sustained load, 1M total connections
- **Tool:** Custom instrumentation in `TCPEndpoint.handleSegment()`

**Why 72% Reduction is Achievable:**
- Timer overhead currently accounts for ~18% CPU (see profiling data)
- V2 TimerWheel reduces this to <1% CPU (theoretical)
- This frees CPU for packet processing, reducing queuing delays
- Target is ambitious but justified by algorithmic improvements

### 4.2 Throughput Stability
- **Test:** 100k connection benchmark with concurrency scaling (10, 50, 100, 250, 500 concurrent workers)
- **Success Criteria:** CPS remains within ±5% across all concurrency levels
- **Monitoring:** Sample CPS every 1 second, plot distribution to detect "sawtooth" patterns

### 4.3 Kernel Profiling
- Final `perf` profile to confirm `Wyhash` and `Timer` symbols have dropped below the Top 5.

---

## Phase 5: Rollback & Contingency Planning

### Rollback Triggers

| Scenario | Threshold | Action | Recovery Time |
|----------|-----------|--------|---------------|
| **Phase 2 Integration Regression** | >5% CPS reduction after Phase 2.1 | Revert to old `TimerQueue` implementation | 1 hour |
| **Phase 3 Sharding Latency Spike** | P99 latency >2× baseline | Disable sharding, use single global table | 30 minutes |
| **Memory Leak** | RSS growth >10% over 1-hour test | Revert pooling (Phase 3.1) | 2 hours |
| **Correctness Bug** | TCP state machine violation | **STOP ALL WORK**, root cause analysis | TBD |

### Feature Flags (Compile-Time)

To enable safe experimentation and rollback, implement these compile-time toggles:

```zig
// build.zig
pub const BuildOptions = struct {
    use_timer_wheel_v2: bool = true,  // Phase 1
    enable_endpoint_pooling: bool = true,  // Phase 3.1
    shard_count: u16 = 256,  // Phase 3.2 (1 = disabled, 256 = full)
    enable_lazy_alloc: bool = true,  // Phase 3.3
};
```

**Rollback Procedure:**
1. Change flag in `build.zig`
2. Run `zig build` to recompile
3. Deploy new binary
4. Verify regression is resolved
5. Document root cause in post-mortem

### A/B Testing Strategy

For production deployments:
- Run Phase 1+2 (TimerWheel) on 10% of traffic for 24 hours
- Monitor error rates, latency P99, CPS throughput
- If metrics improve by >20%, roll out to 100%
- If metrics degrade by >5%, immediate rollback

---