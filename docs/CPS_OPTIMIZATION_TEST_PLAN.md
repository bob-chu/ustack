# Test Plan: 100k CPS TCP Optimization

---
**Document Version:** v1.0  
**Last Updated:** February 2, 2026  
**Status:** 🏗️ PROPOSED  
**Author:** Sisyphus (AI Agent)  
**Objective:** Validate architectural changes and ensure the 100k CPS target is met without regressions.

---

## 0. Test Execution Sequence

Tests must be executed in the following order to ensure dependencies are validated before dependent components:

### Phase 1: Pre-Integration (Baseline)

1. **UT-WHEEL-*** → All unit tests for TimerWheel V2 (Section 1)
   - **Gate:** ALL must pass before proceeding
   - **Runtime:** ~5 seconds per test
   
2. **Baseline Performance Capture** → Establish current-master metrics
   - Run 100k connections @ concurrency 100 on current master
   - Record: CPS (avg/min/max), P50/P99 latency, CPU %, memory RSS
   - **Critical:** Without baseline, cannot measure improvement

### Phase 2: Post-Integration (Validation)

3. **IT-TCP-*** → Integration tests (Section 2)
   - Verify timer lifecycle in real TCP scenarios
   - **Gate:** ALL must pass before proceeding

4. **IT-POOL-*** and **IT-SHARD-*** → Scalability tests (Section 2)
   - Run only if Phase 3 (Pooling/Sharding) is implemented
   
5. **Regression Suite** → Full `zig build test` (Section 4)
   - **Gate:** Zero failures allowed
   - Detects unintended breakage from changes

### Phase 3: Performance Validation (Final)

6. **Section 3.1** → CPS Throughput
7. **Section 3.2** → Latency Distribution
8. **Section 3.3** → Resource Leak Detection (long-running)

**STOP Conditions:**
- Any P0/P1 failure → STOP, triage immediately (see Section 6)
- >5% CPS regression → STOP, investigate before continuing

---

## Test-to-Code Mapping

| Test ID | Implementation Location | Status | Notes |
|---------|-------------------------|--------|-------|
| **UT-WHEEL-1** | `src/time.zig:306` | ✅ Implemented | Basic schedule/fire/cancel |
| **UT-WHEEL-2** | - | ❌ Missing | Bitmask `findNext` verification |
| **UT-WHEEL-3** | `src/time.zig:359` | ✅ Implemented | Cascading L0→L1→L2 |
| **UT-WHEEL-4** | - | ❌ Missing | Zero-delay clamping test |
| **UT-WHEEL-5** | - | ❌ Missing | `tickTo()` bulk advancement |
| **UT-WHEEL-6** | - | ❌ Missing | Wraparound at 2^64 boundary |
| **IT-TCP-1** | - | ❌ Missing | Timer cancellation on close |
| **IT-TCP-2** | - | ❌ Missing | Retransmit via TimerWheel |
| **IT-TCP-3** | - | ❌ Missing | TIME-WAIT cleanup |
| **IT-POOL-1** | - | ❌ Missing | Endpoint recycling |
| **IT-SHARD-1** | - | ❌ Missing | Shard distribution |

**Action Items:**
- Implement missing tests (UT-WHEEL-2, 4, 5, 6)
- Create integration test harness for IT-TCP-* tests
- Add shard distribution verification to test suite

---

## 1. Unit Testing (Component Level)
*Target: `src/time.zig` (TimerWheel V2)*

| Test ID | Scenario | Success Criteria |
| :--- | :--- | :--- |
| **UT-WHEEL-1** | Basic Schedule/Fire | Timer scheduled for +10ms fires exactly at +10 ticks. |
| **UT-WHEEL-2** | Bitmask `findNext` | Search skips 200 empty slots in Level 0 in $O(1)$ time. |
| **UT-WHEEL-3** | Cascading | Timer scheduled for +1000ms (Level 1) correctly moves to Level 0 and fires. |
| **UT-WHEEL-4** | Zero-Delay | `delay_ms = 0` fires in the current slot or immediately. |
| **UT-WHEEL-5** | Bulk Advancement | `tickTo()` correctly processes multiple expired slots without looping. |
| **UT-WHEEL-6** | Wraparound | Timers scheduled across the $2^{64}$ tick boundary function correctly. |

---

## 2. Integration & Lifecycle Testing
*Target: `src/stack.zig` and `src/transport/tcp.zig`*

| Test ID | Scenario | Success Criteria |
| :--- | :--- | :--- |
| **IT-TCP-1** | Timer Cancellation | Closing a socket cancels retransmit/keep-alive timers immediately. |
| **IT-TCP-2** | Retransmit Trigger | Drop a SYN-ACK; verify the retransmit timer fires via the new wheel. |
| **IT-TCP-3** | Time-Wait Cleanup | Sockets in `TIME_WAIT` are correctly removed after the configured duration. |
| **IT-POOL-1** | Endpoint Recycling | Verify pooled endpoints are correctly reset (clearing old state/timers) before reuse. |
| **IT-SHARD-1** | Table Distribution | Verify `accept()` calls distribute endpoints evenly across all 256 shards (hash distribution test). |

---

## 3. Performance & Stress Testing
*Target: `example_ping_pong`*

### 3.1 Throughput (CPS) Verification
- **Baseline**: Run 100k connections, concurrency 100 on current master.
- **Milestone 1**: Post-TimerWheel integration. Expected gain: **+50% CPS**.
- **Milestone 2**: Post-Pooling & Sharding. Expected gain: **Reach 100k CPS**.

### 3.2 Latency Distribution Analysis
- Use `stats.global_stats.latency` to track:
    - **P99 Handshake Latency**: Verify no spikes > 50µs.
    - **Stability**: Average latency should remain constant as connection count increases.

### 3.3 Resource Leak Detection
- Run 1 million connections over 10 minutes.
- Monitor:
    - Memory RSS (should remain stable due to pooling).
    - FD count (should not leak sockets).
    - Timer count (should remain proportional to active connections).

---

## 4. Regression & Compliance
*Target: Existing Test Suite*

- **Protocol Compliance**: Run `zig build test` to ensure existing TCP state machine logic is untouched.
- **Port Reuse**: Run `src/transport/tcp_reuse_test.zig` to ensure `SO_REUSEADDR` logic still functions with sharded tables.

---

## 5. Environment Verification (MANDATORY)

All performance tests (Section 3) **MUST** run in a controlled environment to ensure reproducibility:

### Hardware Requirements
- **Testbed:** Dedicated Docker container (`my-ubuntu`) OR bare-metal server
- **CPU:** Single core sufficient (ustack is single-threaded by design)
  - Recommended: 8+ cores for isolated testing (pin ustack to core 0, isolate system tasks)
- **Memory:** 16GB RAM minimum
- **Network:** Local loopback OR dedicated `veth` pair (no external network noise)

**Single-Threaded Architecture:** ustack runs on a single CPU core using an event loop (libev/libuv). CPU isolation ensures no scheduler interference during benchmarks.

### System Configuration (Mandatory)

```bash
# 1. CPU Isolation (REQUIRED for reproducible results)
# Pin ustack to core 0, isolate from system interrupts
sudo taskset -c 0 ./zig-out/bin/benchmark_cps

# 2. IRQ Affinity (REQUIRED for AF_PACKET/AF_XDP)
# Move NIC interrupts away from ustack core
echo "1-7" | sudo tee /proc/irq/*/smp_affinity_list

# 3. Disable CPU Frequency Scaling (REQUIRED)
sudo cpupower frequency-set -g performance

# 4. Disable Transparent Huge Pages (RECOMMENDED)
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

# 5. Increase File Descriptor Limits
ulimit -n 1048576
```

**Note:** ustack uses a single-threaded event loop. CPU isolation prevents scheduler noise, not for parallelism.

### Monitoring (During Test Runs)

```bash
# Terminal 1: Run benchmark
./benchmark_cps --connections 100000 --concurrency 100

# Terminal 2: Profile with perf
sudo perf stat -p $(pgrep benchmark_cps) -- sleep 60

# Terminal 3: Monitor resource usage
watch -n 1 'ps aux | grep benchmark_cps | grep -v grep'
```

**Validation:** Before running any performance test, verify:
- [ ] CPU governor is "performance" (`cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`)
- [ ] `taskset` shows correct CPU affinity (`taskset -p $(pgrep benchmark_cps)`)
- [ ] No other CPU-intensive processes running (`top` shows <5% system load)

---

## 6. Failure Triage Protocol

When a test fails, follow this decision tree:

| Severity | Response Time | Action | Example |
|----------|--------------|--------|---------|
| **P0 (Crash/Corruption)** | IMMEDIATE | **STOP ALL TESTING**. Root cause analysis required. Revert changes if no fix within 4 hours. | Segfault in timer callback, memory corruption detected |
| **P1 (Functional Failure)** | Within 24 hours | Block dependent tests. Fix required before merge. Create tracking issue. | Timer fails to fire, TCP state machine violation |
| **P2 (Performance Regression)** | Within 3 days | Document regression. Fix before merge. May require architecture review. | CPS drops to 70k (expected 100k) |
| **P3 (Edge Case)** | Best effort | Create ticket. Defer if non-critical. Document limitation in release notes. | Wraparound at 2^64 ticks (49 days runtime) |

### Triage Checklist

1. **Reproduce:** Can the failure be reproduced reliably? (Run test 3× times)
2. **Isolate:** Is this a new failure, or pre-existing? (Check if test passes on `master` branch)
3. **Impact:** How many users/scenarios affected? (Edge case vs common path)
4. **Blame:** Which phase introduced the failure? (Use `git bisect` if needed)

### Escalation Path

- **P0/P1:** Notify team lead immediately, schedule emergency triage meeting
- **P2:** Daily standup discussion, assign owner
- **P3:** Document in backlog, prioritize in next sprint

---

## 7. Automation Strategy

| Test Category | Automation | Gating | Runtime | Notes |
|---------------|------------|--------|---------|-------|
| **UT-WHEEL-*** | ✅ CI (GitHub Actions) | ✅ Pre-merge | ~30 seconds | Part of `zig build test` |
| **IT-TCP-*** | ✅ CI | ✅ Pre-merge | ~2 minutes | Integration test suite |
| **IT-POOL/SHARD** | ⚠️ Manual | ❌ Post-merge | ~5 minutes | Requires multi-core Docker setup |
| **Section 3.1** (CPS) | ⚠️ Manual | ❌ Post-merge | ~10 minutes | Requires dedicated hardware |
| **Section 3.2** (Latency) | ⚠️ Manual | ❌ Post-merge | ~10 minutes | Requires dedicated hardware |
| **Section 3.3** (Leak) | ✅ CI (Nightly) | ⚠️ Non-blocking | ~10 minutes | Too slow for PR checks, run nightly |
| **Regression** | ✅ CI | ✅ Pre-merge | ~5 minutes | Full `zig build test` |

**CI Configuration:**
```yaml
# .github/workflows/test.yml
name: Test Suite
on: [push, pull_request]
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - run: zig build test  # UT-WHEEL-*, IT-TCP-*
      
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - run: zig build test_integration  # Custom target
      
  nightly-leak-detection:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/leak_test.sh  # 10-minute stress test
```

**Manual Test Procedure:**
1. Reserve dedicated test machine (avoid noisy neighbors)
2. Apply mandatory environment configuration (Section 5)
3. Run performance tests (Section 3.1, 3.2)
4. Capture results in `docs/benchmarks/YYYY-MM-DD.md`
5. Compare against baseline (`docs/benchmarks/baseline.md`)

---