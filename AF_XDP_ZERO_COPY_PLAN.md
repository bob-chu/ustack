# AF_XDP Zero-Copy Plan (ustack)

## Goal

Make AF_XDP data path truly zero-copy (or as close as Linux allows):

- **RX:** avoid `UMEM -> Cluster` memcpy
- **TX:** avoid `Cluster/View -> UMEM` memcpy when possible
- Preserve correctness and lifetime safety in ustack's single-threaded event loop model.

---

## Current bottlenecks / copy points

In current code:

- `src/drivers/linux/af_xdp.zig::poll()` copies RX frame into cluster (`@memcpy`).
- `src/drivers/linux/af_xdp.zig::writePacket()` copies payload into UMEM (`@memcpy`).
- Transport RX paths (notably UDP/TCP queueing) can clone/copy payload views.
- UMEM frame ownership/lifetime is not tracked through `VectorisedView` consumption.

---

## Architecture change

Introduce AF_XDP external-frame ownership integrated with `VectorisedView.consumption_callback`.

### Core idea

1. Represent packet data view directly over UMEM slices.
2. Attach release callback so frame returns to fill/free only after stack/app consumption completes.
3. Keep copy fallback for paths that cannot guarantee short/lifetime-safe retention.

---

## Phase 0 — Baseline instrumentation

Add stats counters:

- `af_xdp_rx_copy_bytes`
- `af_xdp_tx_copy_bytes`
- `af_xdp_rx_zerocopy_pkts`
- `af_xdp_tx_zerocopy_pkts`
- `af_xdp_umem_ref_hold`
- `af_xdp_umem_ref_release`

**Acceptance:** counters visible and updating under ping_pong/uperf.

---

## Phase 1 — RX zero-copy core

### 1. External frame metadata

Add a small frame-handle type in `af_xdp.zig`:

- driver pointer
- frame addr/index
- length
- state (`inflight`, `returned`)

### 2. Build `VectorisedView` directly from UMEM

In `poll()`:

- replace RX `@memcpy` to cluster with UMEM-backed view (`cluster = null`, `view = umem slice`)
- attach consumption callback that recycles the frame.

### 3. Defer recycle to callback

- remove immediate frame return for zero-copy RX packet
- recycle only when callback fires.

### 4. Safety checks

- double-return guard
- debug assertions for frame state.

**Acceptance:** AF_XDP RX fast path has no payload memcpy; 60s test stable.

---

## Phase 2 — Transport compatibility for external views

Transport currently assumes cloned/owned payload in some places.

### UDP

- In `src/transport/udp.zig::handlePacket`, avoid unconditional `cloneInPool()` for AF_XDP-safe external view.
- Queue external view directly when lifetime is callback-managed.

### TCP

- In established RX path (`src/transport/tcp.zig`), add fast-path enqueue without clone when view is lifetime-safe.
- Keep clone fallback for long-lived/OOO-risk cases.

### OOO retention policy

- If OOO queue pressure rises (or retention likely long), copy to cluster fallback to avoid UMEM starvation.

**Acceptance:** TCP/UDP functional tests pass with mixed zero-copy + fallback paths.

---

## Phase 3 — TX zero-copy

### 1. UMEM-origin payload detection

- Detect outgoing views already backed by AF_XDP UMEM.

### 2. Descriptor-native TX

- Build TX descriptors directly from UMEM-backed payload where possible.
- Avoid payload memcpy for eligible buffers.

### 3. Header strategy

Start with a practical approach:

- keep simple copy fallback for non-UMEM headers,
- then optimize with UMEM headroom/prepend plan.

### 4. Completion lifecycle

- Release frame refs on completion ring
- trigger completion callbacks for app-origin zero-copy buffers.

**Acceptance:** measurable reduction of TX memcpy and driver CPU cycles.

---

## Phase 4 — API contract and docs

Define/clarify `writeZeroCopy` contract:

- caller buffer valid until callback
- callback is sole completion signal
- fallback copy behavior documented when zero-copy preconditions are not met.

Add example usage in AF_XDP example app.

---

## Phase 5 — Verification matrix

### Functional

- ping_pong CPS
- uperf UDP (`64`, `9000`)
- uperf TCP (MTU `1500`, `9000`)

### Stability

- 60s and 10min soak tests
- no leaks, no frame double-release.

### Correctness

- tcpdump-based flag consistency checks (SYN/SYN+ACK/ACK/PSH/FIN)

### Performance

- perf before/after
- memcpy hotspots reduced
- cycles/packet reduced on AF_XDP path.

---

## Risks and mitigations

1. **UMEM starvation due to long-lived buffers**
   - Mitigate with OOO threshold + copy fallback.

2. **Lifetime bugs / double recycle**
   - State machine + assertions + counters.

3. **Transport assumptions on ownership**
   - Explicit checks and staged rollout (UDP first, TCP next).

---

## Recommended execution order

1. Phase 0 instrumentation
2. Phase 1 RX zero-copy core
3. Phase 2 UDP compatibility
4. Phase 2 TCP compatibility
5. Phase 3 TX zero-copy
6. Phase 4 docs/API finalization
7. Phase 5 full validation and perf report
