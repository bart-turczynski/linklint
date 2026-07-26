# Security Policy

## Supported versions

`linklint` is distributed through npm. Security fixes are made against the
latest released version; please upgrade to the most recent release before
reporting.

| Version                | Supported          |
| ---------------------- | ------------------ |
| Latest npm release     | :white_check_mark: |
| Older releases         | :x:                |
| `0.x` pre-1.0 dev tags | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Preferred channel — **GitHub private vulnerability reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.

This opens a private security advisory visible only to the maintainers.

If you cannot use that channel, email the maintainer at
**bartek@turczynski.pl** instead.

## What to expect

- We aim to acknowledge a report within **7 days**.
- We will investigate, work on a fix, and coordinate disclosure with you.
- We are happy to credit reporters in the release notes unless you prefer to
  remain anonymous.

## Scope

`linklint` is an offline URL inspector. Its core opens no network connections,
handles no credentials, and performs no runtime filesystem I/O, so its security
surface is the safe handling of untrusted URL input.

In scope — please report:

- **Input that escapes the never-throws guarantee.** `inspect()` is documented
  to return `status: "invalid"` rather than throw on *any* input, including a
  non-string. An input that throws, hangs, or exhausts memory breaks the
  central safety property, and is the highest-value report you can send.
- **Algorithmic complexity / ReDoS.** An input whose inspection time grows
  superlinearly, defeating the documented per-call budget.
- **Verdict-integrity flaws in the opt-in transport layer.** In
  `@linklint/online`: any way to defeat exact-URL authorization, DNS pinning,
  original-host TLS validation, or credential stripping — for example, causing
  a request to a host the caller never authorized.
- **Data escaping the core.** Any path by which core transmits, logs, or
  persists the URL it was given.

Out of scope — these are correctness issues, not vulnerabilities. Please open a
normal issue instead:

- **A deceptive URL that linklint does not flag** (a false negative), or a
  benign URL that it does (a false positive). Detection coverage is a stated,
  bounded claim — see [*What linklint does not
  do*](./README.md#what-linklint-does-not-do), stated canonically in
  [`docs/architecture.md` §1.1](./docs/architecture.md). A missed URL is a gap in
  a documented boundary, not a bypass of a security control. Known misses are
  tracked in the open, including a committed corpus of them at
  `packages/core/test/corpus/embarrassment.ts`.
- **A vulnerability in a URL you inspected.** linklint reports on strings; it
  neither hosts nor fetches them.

If you are unsure which category a finding falls into, use the private channel.
We would rather triage a correctness bug in private than miss a real one.

## Handling of untrusted data

Do not include secrets, credentials, tokens, or private customer data in
issues, pull requests, logs, or `_scratch/`.
