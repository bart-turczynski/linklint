# Online packaging and runtime boundary

**Status:** accepted
**Date:** 2026-07-17
**Decision issue:** `LINK-ryfztgke`

## Context

`linklint` already exposes the pure `inspectAsync()` runner and caller-supplied
`Enricher` seam. Those APIs do not perform network I/O themselves. Resolution,
provider reputation, caller-owned feed mirrors, and monitoring now need concrete
runtime ownership without weakening the synchronous `inspect()` boundary or
silently making the CLI and MCP server network-capable.

The decision has to account for two different kinds of online work:

- bounded, caller-authorized work for one inspection, such as DNS, redirects,
  TLS, RDAP, or a local threat-feed lookup; and
- long-running work with durable checkpoints, tenancy, retries, alerts, and
  publication state.

They do not have the same trust, storage, deployment, or operations boundary.

## Decision

Adopt three one-way runtime boundaries:

```text
browser / offline CLI / offline MCP ───────────────► linklint

server app / opt-in online CLI ─► @linklint/online ─► linklint

monitoring service ─────────────► @linklint/online ─► linklint
        │
        └── owns database, queues, checkpoints, outbox, tenancy, and secrets
```

### 1. `linklint`: pure contracts and orchestration

The existing core package remains the portable source of truth. It owns:

- synchronous `inspect()` and every deterministic detector, policy, score, and
  schema projection;
- versioned, source-neutral enrichment outcome/evidence contracts;
- `inspectAsync()` and deterministic orchestration of caller-supplied work;
- portable cache/governor interfaces and dependency-free in-memory
  implementations; and
- validation that turns malformed or failed enrichment into explicit outcomes.

Core does not own DNS, sockets, `fetch`, provider SDKs, credentials, mirror
updaters, persistent stores, browser automation, or monitor state. Importing
core, calling `inspect()`, or calling `inspectAsync()` without configured work
continues to perform zero network I/O. `inspect()` stays synchronous and its
output remains deterministic apart from already documented time-relative
metadata.

### 2. `@linklint/online`: explicit per-inspection online capabilities

The sibling package `packages/online` is scaffolded as `@linklint/online`. It is
the only built-in library package that may contain concrete network clients.
Its root is currently side-effect free and intentionally exposes no online
capability; the internal deterministic transport harness shipped first so L0
can be implemented without live network access. The package owns:

- the L0 DNS-pinned HTTP(S) authorization and connection boundary;
- DNS, TLS, HTTP, redirect, and response-evidence adapters;
- RDAP and other explicitly enabled provider adapters;
- caller-owned threat-feed mirror lookup and update implementations;
- Node persistent cache/store adapters; and
- deterministic injected resolver, connector, clock, and provider fixtures.

It depends on the public `linklint` contract. `linklint` never imports it, and
`@linklint/online` never imports CLI, MCP, or monitoring code. Source-specific
adapters may depend on the shared safe transport, but provider code cannot
bypass that transport when it connects to an inspected destination.

The package is Node/server-side (Node 24 or newer). It intentionally has no
browser export condition: browser `fetch` does not expose the address pinning,
socket selection, SNI, and certificate controls required by L0. Browser clients
run core locally and, when a user explicitly opts in, call a caller-owned
backend that applies the online boundary.

The public export map will expand only as each capability ships and is
intentionally capability-oriented:

| Export | Ownership |
|--------|-----------|
| `@linklint/online` | Public online configuration, consent, source metadata, and composition APIs |
| `@linklint/online/transport` | L0 transport ports, policy, and Node implementation |
| `@linklint/online/resolution` | Redirect, refresh, wrapper, and response-evidence adapters |
| `@linklint/online/reputation` | RDAP, DNS/TLS, and provider adapter factories |
| `@linklint/online/mirrors` | Caller-owned mirror stores, lookup adapters, and updater APIs |

Only these declared subpaths are public; consumers do not deep-import package
internals. Concrete symbol names remain with their implementation tickets, but
the ownership and export categories above are fixed by this decision.

### 3. Monitoring: a separate deployable service

Long-running monitoring lives under a separate service/runtime boundary, not
inside core, `@linklint/online`, `@linklint/cli`, or `@linklint/mcp`. The service
may reuse core contracts and online clients, but it alone owns:

- scheduler leases, durable checkpoints, queues, and crash recovery;
- tenant isolation, retention/deletion, fairness, and cost budgets;
- candidate lifecycle and human-review state;
- delivery retries, an outbox, alerts, and signed publication state;
- migrations, backups, observability, and deployment configuration; and
- secret references resolved by its deployment environment.

This service is not an `inspectAsync()` loop and its stateful APIs are not
re-exported from either library package. Deployment topology and storage
technology remain N0 decisions; the ownership boundary does not.

## Consumer boundaries

| Consumer | Decision |
|----------|----------|
| Browser/library | Import `linklint` only. Online work goes through a caller-owned backend after an explicit user action. |
| Existing `@linklint/cli` | Remains offline and depends only on `linklint`; `linklint check` never gains an implicit online mode. |
| Opt-in online CLI | A separately installed future channel (for example `@linklint/online-cli`) depends on `@linklint/online`; it must require an explicit online command/flag and operation authorization. |
| Existing `@linklint/mcp` | Remains local-only and offline. It does not import or dynamically load `@linklint/online`. |
| Future agent-facing online channel | Must be a separate package/service with per-operation caller authorization. Merely enabling agent mode or calling an offline check is not consent to fetch a destination or disclose a URL. |
| Server application | Composes named `@linklint/online` capabilities at its application boundary and supplies policy, storage, clock, credentials, and consent explicitly. |
| Monitoring worker | Runs in the monitoring service and uses only the specific core/online contracts required by each source. |

Separating the online CLI and any future online MCP surface preserves truthful
installation and runtime claims for the existing offline packages. It also
prevents a transitive dependency or configuration change from quietly adding
network authority to an agent process.

## Opt-in and authorization rules

Installation or construction is never authorization to make a request.

- No package performs network I/O at import time or discovers adapters from the
  environment automatically.
- A caller supplies the exact adapters to run. An empty set is offline and
  preserves the current `inspectAsync(input) === inspect(input)` contract.
- Every operation that connects to an inspected destination carries explicit
  caller authorization and passes L0 before each connection and redirect hop.
- Every provider operation declares its disclosure shape. Sending a full URL,
  watchlist, or other sensitive subject requires explicit consent for that
  operation; destination-fetch authorization does not imply provider-disclosure
  consent, or vice versa.
- Network, DNS, TLS, provider, quota, timeout, parser, and missing-credential
  failures are incomplete/skipped outcomes with machine-readable causes. Only
  policy refusal, such as a prohibited address, is `blocked`. A no-match is
  evidence about one source at one time, never a safety claim.
- Every resolved hop is fed back through the offline `inspect()` pipeline. Online
  evidence extends the lexical result and never replaces it.

## Configuration, credentials, and storage

Library configuration is explicit and typed. Libraries receive dependencies
through constructors/factories; they do not read process-wide environment
variables, default credential chains, home directories, or global config files.
CLI/server/service composition roots may translate their own environment or
secret-manager configuration into those typed inputs.

Credentials are caller-owned and source-scoped. They must not appear in
`InspectResult`, evidence payloads, errors, telemetry, cache keys, fixture
snapshots, or logs. Provider authorization headers are sent only to the selected
provider and are always stripped before a destination request or cross-origin
redirect. Missing credentials cause an explicit skipped outcome rather than an
interactive prompt or fallback to an anonymous service.

Core keeps portable storage interfaces. `@linklint/online` may provide Node
implementations, but a caller supplies the database, directory, or store. Feed
snapshots and cache contents are never bundled in npm artifacts. The monitoring
service owns its durable database and outbox; it may reference online mirror
stores but does not transfer their ownership to core.

## Licensing, privacy, and commercial modes

There is no package-wide claim of k-anonymity or provider compatibility. Every
source adapter publishes machine-readable metadata for:

- source identity and evidence scope;
- data sent off-machine (URL, host, prefix, client IP, or watchlist);
- credential and consent requirements;
- terms/licence mode, including commercial-use restrictions;
- attribution, retention, caching, and redistribution constraints; and
- freshness and no-match semantics.

Adapter construction or execution refuses a missing/incompatible required mode;
terms are an executable configuration gate, not a documentation-only warning.
The repository ships integration code, not credentials or provider datasets.
Caller-owned mirrors stay caller-owned and are never silently redistributed.
Adapters whose terms cannot support the selected mode remain parked rather than
being enabled with weaker defaults.

## Shipped `inspectAsync()` foundation

`inspectAsync()` remains in `linklint`; it is not moved into the online package.
K6-K9 completed its pure contract in place:

1. Schema 1.3 carries versioned structured outcomes/evidence alongside the
   legacy `EnricherFinding` scoring projection.
2. Deterministic dependency stages expose prior source outcomes and apply
   subject-aware suppression to discovered destinations.
3. Every configured source is bounded by default, and provider, governor, cache,
   and orchestration failures become explicit degradation outcomes.
4. Promise-capable caches store and revalidate normalized reports and support
   response-driven positive/no-hit lifetimes.
5. Existing caller-supplied legacy enrichers remain supported through a
   documented compatibility window with visibly incomplete provenance.
6. `inspectAsync()` with no configured work remains byte-identical to
   `inspect()`, preserving the synchronous API and offline package exports.

New `@linklint/online` adapters must emit only the structured contract. Remove or
narrow the legacy shape only through an explicit public-contract release with
migration notes and contract tests. See
[`enrichment-outcomes.md`](enrichment-outcomes.md) for the shipped schema,
validation, degradation, orchestration, and cache contract.

Epic L's deterministic transport harness is shipped. The current delivery
frontier is the L0 safe transport boundary. See
[`online-roadmap.md`](online-roadmap.md) for the resume order and live FP issue
mapping.

## Enforcement and verification

- Core compatibility tests continue to reject Node built-ins, network modules,
  runtime filesystem access, native dependencies, and imports of
  `@linklint/online`.
- Online transport/provider tests use injected deterministic fixtures; CI needs
  no live network, provider account, credential, or feed mirror.
- The L0 suite proves address classification, DNS pinning, original-host SNI and
  hostname verification, per-hop reauthorization, credential stripping, and
  mandatory hop/byte/decompression/time budgets.
- Package-export tests prevent accidental deep imports and prevent browser,
  offline CLI, and MCP bundles from resolving online implementations.
- Monitoring acceptance tests use local fixtures for leases, replay,
  idempotency, tenancy, review, delivery, and publication; they do not weaken
  per-call online contracts.

## Consequences

The split adds a package and, later, a deployable service, but makes network
authority visible in dependency graphs and installation choices. Core stays
portable and honestly offline; server users get maintained adapters without
copying transport security; browser and agent surfaces cannot accidentally gain
unsafe fetch authority; and monitoring can meet durable operational requirements
without distorting the per-inspection API.
