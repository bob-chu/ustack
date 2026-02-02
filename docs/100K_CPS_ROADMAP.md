# 100k CPS Optimization Initiative — Master Roadmap

---
**Document Version:** v1.0  
**Last Updated:** February 2, 2026  
**Status:** 🏗️ IN PROGRESS  
**Initiative Lead:** Sisyphus (AI Agent)  
**Target:** Achieve 100,000 Connections Per Second (CPS) with stable sub-10µs latency

---

## Overview

This initiative targets achieving **100,000 connections per second (CPS)** through architectural improvements to timer management, memory allocation, and connection sharding. The work is organized into **4 phases** spanning timer optimization, stack integration, scalability enhancements, and comprehensive validation.

**Architecture Note:** ustack is a **single-process, single-thread network stack** designed for event loop architectures (similar to nginx, Redis, HAProxy). High performance comes from eliminating context switches, lock contention, and cache coherency overhead — not from multi-core parallelism. The entire stack runs on one CPU core.

### Business Case

**Current State:** ustack achieves ~80k CPS with P99 latency spikes of ~180µs  
**Target State:** 100k+ CPS with P99 latency <50µs  
**Value Proposition:** Enables ustack to compete with kernel TCP stacks for high-performance applications (load balancers, API gateways, CDN edge nodes)

### Success Metrics

| Metric | Baseline | Target | Measurement Method |
|--------|----------|--------|-------------------|
| **Connections/Sec** | 80,000 CPS | 100,000+ CPS | Benchmark (10-min sustained load) |
| **P99 Handshake Latency** | 180µs | <50µs | Instrumentation in `TCPEndpoint.handleSegment()` |
| **CPU Overhead (Timers)** | ~18% | <1% | `perf` profiling |
| **Memory per Connection** | ~2.5KB | <2.0KB | Pooling + lazy allocation |

---

## Document Map

Read these documents in order based on your role:

### 1. [TIMER_WHEEL_DESIGN.md](TIMER_WHEEL_DESIGN.md)
**Audience:** Engineers implementing or reviewing the timer system  
**Content:** Technical design of the hierarchical timer wheel (V2) with bitmask optimization  
**Status:** 🏗️ Implementation in progress (blocked by compilation errors)

**Key Sections:**
- Section 1.1: Problem Statement — Why timer optimization is critical
- Section 2: Bitmask data structures and O(1) complexity explanation
- Section 3.3: Cascading mechanics (how timers move between levels)
- Section 5: Memory safety contract and failure modes

---

### 2. [CPS_OPTIMIZATION_PLAN.md](CPS_OPTIMIZATION_PLAN.md)
**Audience:** Project managers, engineers planning implementation  
**Content:** Phased implementation roadmap with dependencies and rollback strategies  
**Status:** 🏗️ Status dashboard tracks progress across all phases

**Key Sections:**
- Status Dashboard: Real-time view of phase completion
- Dependency Graph: Critical path vs parallel work tracks
- Resource Planning: Effort estimates and risk assessment
- Phase 5: Rollback procedures and feature flags

---

### 3. [CPS_OPTIMIZATION_TEST_PLAN.md](CPS_OPTIMIZATION_TEST_PLAN.md)
**Audience:** QA engineers, test automation developers  
**Content:** Testing and validation strategy from unit → integration → performance  
**Status:** 🏗️ Test mapping identifies missing test coverage

**Key Sections:**
- Section 0: Test execution sequence (order of operations)
- Test-to-Code Mapping: Links test IDs to actual file locations
- Section 5: Mandatory environment configuration for reproducible benchmarks
- Section 6: Failure triage protocol with severity levels

---

### 4. [TIME_WAIT_REUSE_DESIGN.md](TIME_WAIT_REUSE_DESIGN.md)
**Audience:** Engineers working on TCP state machine optimizations  
**Content:** Design for TIME-WAIT state optimization (future work)  
**Status:** 📝 Design phase (not yet implemented)

**Why This Matters:** Without TIME-WAIT reuse, connections linger for 60-120 seconds after close, exhausting ephemeral port range and blocking 100k CPS target.

---

## Quick Start Guide

### For Implementers (New to Project)
1. **Read:** `TIMER_WHEEL_DESIGN.md` Section 1 (Executive Summary + Problem Statement)
2. **Understand:** `CPS_OPTIMIZATION_PLAN.md` Status Dashboard to see current state
3. **Check:** `CPS_OPTIMIZATION_TEST_PLAN.md` Test-to-Code Mapping to find missing tests
4. **Start Work:** Pick a phase from the Status Dashboard with status "⚠️ CAN START"

### For Reviewers (Evaluating Proposed Changes)
1. **Focus:** `TIMER_WHEEL_DESIGN.md` Section 6 (API Contract & Semantics)
2. **Verify:** Memory safety requirements in Section 5
3. **Check:** `CPS_OPTIMIZATION_TEST_PLAN.md` to ensure proposed tests are adequate

### For QA (Setting Up Test Environment)
1. **Mandatory:** `CPS_OPTIMIZATION_TEST_PLAN.md` Section 5 (Environment Verification)
2. **Follow:** Section 0 (Test Execution Sequence) for proper test ordering
3. **Use:** Section 6 (Failure Triage Protocol) when tests fail

---

## Current Status Snapshot

| Phase | Component | Status | Blocking Issues |
|-------|-----------|--------|----------------|
| **1** | TimerWheel V2 | ✅ COMPLETE | Fixed `@ctz` and `nextExpiration()` bugs |
| **2** | Stack Integration | ✅ COMPLETE | Integrated into `Stack.timer_queue`, fixed safety bugs |
| **3** | Pooling/Sharding | 🏗️ IN PROGRESS | Sharding COMPLETE, Pooling PENDING |
| **4** | Validation | ❌ NOT STARTED | Depends on Phase 3.1 |

**Next Immediate Actions:**
1. **Fix Phase 1 blockers** (see `TIMER_WHEEL_DESIGN.md` Section 7)
2. **Establish performance baseline** (see `CPS_OPTIMIZATION_TEST_PLAN.md` Section 0)
3. **Implement missing tests** (UT-WHEEL-2, 4, 5, 6 from Test-to-Code Mapping)

---

## Terminology & Glossary

| Term | Definition | Reference |
|------|------------|-----------|
| **CPS** | Connections Per Second — rate of new TCP handshakes completed | - |
| **TimerWheel** | Hierarchical timing wheel data structure with O(1) operations | `TIMER_WHEEL_DESIGN.md` Section 2 |
| **Cascading** | Moving timers from higher levels to lower levels during wheel rotation | `TIMER_WHEEL_DESIGN.md` Section 3.3 |
| **SlotMask** | Bitmask (4×u64) tracking which slots contain active timers | `TIMER_WHEEL_DESIGN.md` Section 2.1 |
| **P99 Latency** | 99th percentile latency — 1% of requests are slower than this | - |
| **Sharding** | Splitting connection table into 256 independent buckets | `CPS_OPTIMIZATION_PLAN.md` Phase 3.2 |
| **Pooling** | Pre-allocating endpoint structs to avoid malloc/free per connection | `CPS_OPTIMIZATION_PLAN.md` Phase 3.1 |
| **TIME-WAIT** | TCP state after FIN/ACK, prevents port reuse for 2×MSL (60-120s) | `TIME_WAIT_REUSE_DESIGN.md` |

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| **v1.0** | 2026-02-02 | Initial roadmap document created | Sisyphus |

---

## Related Resources

- **Main README:** [../README.md](../README.md) — ustack architecture overview
- **Agent Guidelines:** [../AGENTS.md](../AGENTS.md) — Build/test commands, code style
- **Source Code:** `src/time.zig` — TimerWheel V2 implementation
- **Benchmarks:** `examples/benchmark_cps.zig` — CPS testing harness (TODO)

---

**Questions or Concerns?**  
This is a living document. If you find gaps, ambiguities, or errors, please update the relevant section and increment the version number.
