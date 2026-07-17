# Online backend roadmap handoff

**Coordinator:** `LINK-ddsnssrd`

**Durable state reconciled:** 2026-07-17

This document is the committed resume map for online resolution, reputation,
and monitoring work. FP remains the live source of truth for issue status and
dependencies; use this document for the architecture boundary, intended order,
and context that should survive individual work sessions.

## Delivered foundation

- `LINK-ryfztgke` is done. The accepted package boundary is:
  - `linklint`: portable contracts, validation, synchronous `inspect()`, and
    pure `inspectAsync()` orchestration;
  - `@linklint/online`: a Node/server package whose deterministic transport
    fixtures and L0 safe destination boundary are shipped; future resolution
    adapters, provider clients, and caller-owned mirror integrations remain
    gated; and
  - a separate deployable monitoring service for durable N state.
- Epic K (`LINK-tfcbqtoy`) is done.
  - K1-K5 provide the original opt-in async pipeline, confidence, cache seam,
    governor, and suppression escape hatch.
  - K6-K9 provide schema 1.3 structured outcomes/evidence, deterministic staged
    orchestration, subject-aware suppression, default bounded degradation, and
    Promise-capable response-driven caching with runtime boundary validation.
- The synchronous product boundary remains unchanged: `inspect()` is
  deterministic and zero-network, and `inspectAsync()` with no configured work
  remains byte-identical to `inspect()`.
- LT (`LINK-jsgadjni`) is done. The internal `@linklint/online` harness provides
  exact-order resolver address changes, pinned connector/SNI assertions,
  streamed HTTP responses, stable operational failures, and a manually advanced
  shared clock without concrete DNS, socket, TLS, HTTP, or `fetch` calls.
- L0 (`LINK-cjkdyxau`) is done. `@linklint/online/transport` requires exact-URL
  authorization for every manual hop, classifies every DNS answer before
  connecting, pins the selected address with original-host TLS identity, strips
  ambient headers, and enforces cumulative hop, byte, decompression, and time
  budgets with structured blocked/incomplete outcomes.
- L2 (`LINK-ehhmrblq`) is done. `@linklint/online/resolution` locally decodes
  exact, version-pinned Microsoft Safe Links and Proofpoint URL Defense formats,
  bounds destination length and nesting, and re-inspects every recovered target
  through offline Layer 1 without calling a vendor or destination service.

## Current execution frontier

The next default task under the coordinator is **claim `LINK-hvirrwxa` (L1)** —
bounded redirect and declarative-refresh chain expansion. L0 and L2 now satisfy
its prerequisites. Every network hop must use L0, receive a new exact-URL
authorization, and be re-inspected offline before the chain continues.

## Epic L dependency path

```text
LT  LINK-jsgadjni
└─► L0  LINK-cjkdyxau
    ├─► L1  LINK-hvirrwxa  ◄─ L2 LINK-ehhmrblq
    │   ├─► L3  LINK-rupjqxus
    │   ├─► L4  LINK-vpqsjtjt
    │   └─► L5  LINK-tibzpdft  ◄─ L0
    └────────────────────────────────────┐
LT + L1 + L2 + L3 + L4 + L5 ───────────► L6 LINK-pzuppjnt
```

- LT supplies deterministic resolver/connector/protocol fixtures.
- L0 owns address classification, DNS pinning, original-host SNI/certificate
  validation, per-hop reauthorization, credential stripping, and mandatory
  byte/decompression/hop/time budgets.
- L2 decodes only exact, version-pinned local wrapper formats. It never calls a
  vendor decoder service.
- L1 expands bounded HTTP redirects and declarative refreshes through L0 and
  re-runs every hop through offline Layer 1.
- L3/L4 add observed redirect/divergence evidence without overstating proof.
- L5 records bounded declared-versus-computed MIME evidence without executing
  content.
- L6 is the deterministic, zero-live-network acceptance gate.

## Other active streams

- Epic M (`LINK-aclentcb`) is source-attributed reputation/infrastructure.
  `LINK-nlnyqofz` (M2 privacy, licensing, provenance, and BYOK contract) must be
  completed before any M provider adapter. M7 live TLS also depends on L0.
- Epic N (`LINK-ioctupur`) is a separate service, not an `inspectAsync()` loop.
  Its foundation starts at `LINK-pjyhavkg` (N0 durable runtime, state, and
  tenancy). N consumes specific contracts and does not depend on all of M.
- Google Safe Browsing M3, VirusTotal M6, and licensed hosting M9b remain parked
  pending explicit product/terms decisions. Former Epic O is outside this
  implementation roadmap.

The default coordinator priority is Epic L (high), then active M work (medium),
then N (low), unless the user explicitly selects another stream.

## Binding invariants

- No concrete network I/O in `linklint`, the existing CLI, or the existing MCP
  server. Concrete online capabilities belong in `@linklint/online` and require
  explicit caller composition.
- Installation, construction, agent mode, or an offline inspection is never
  consent to fetch an attacker-controlled destination or disclose a full URL to
  a provider.
- Every destination connection is authorized by L0 before connect and again at
  every hop. Prohibited addresses are blocked before connection.
- DNS/TLS/provider/timeout/quota/parser failures are explicit incomplete,
  failure, or skipped outcomes. A no-match is not a safety claim. `blocked` is
  reserved for policy/authorization refusal; malicious/suspicious requires
  affirmative evidence.
- Online evidence is additive. It preserves the offline result, re-inspects
  discovered hops through Layer 1, and keeps `checksRun`, `checksSkipped`,
  provenance, freshness, subject, and cause fields honest.
- CI and acceptance tests use deterministic fixtures. They require no live
  credentials, provider account, external network, or bundled provider data.

## Resume procedure

When the coordinator is assigned again:

1. Run `fp guide implement` and `fp context LINK-ddsnssrd`.
2. Run `fp tree LINK-ddsnssrd` and `fp issue show` for the proposed child; do not
   trust this document for status if FP has moved on.
3. Follow the Epic L dependency path above, selecting the first unblocked child
   in the stated order. With LT, L0, and L2 done, the default frontier is L1
   chain expansion (`LINK-hvirrwxa`).
4. Read [`online-runtime-boundary.md`](online-runtime-boundary.md),
   [`architecture.md`](architecture.md), and
   [`enrichment-outcomes.md`](enrichment-outcomes.md) before defining public
   package or evidence contracts.
5. Record start, implementation milestones, verification, and completion in FP.
6. Run `pnpm check` and `git diff --check` before closing an implementation task.

Keep raw investigation in `_scratch/`. Update this committed handoff and the FP
coordinator whenever a gate or execution frontier changes.
