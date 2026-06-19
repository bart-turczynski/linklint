# linklint — project brief

## Origin

This project grows out of the hostname transformer in [punycoder-online](../punycoder-online).
That tool encodes/decodes punycode (A-label ↔ U-label) and normalizes hostnames.
The insight that kicked this off: if `normalize(input) !== input`, something is hiding in the domain.

---

## Core mechanic

Run any hostname through the punycode pipeline. If the display form differs from the
encoded (ACE) form, the domain contains either:

- **Invisible/zero-width characters** — U+200B, U+00AD, U+FEFF, etc.
- **IDN homograph characters** — Cyrillic `а` masquerading as Latin `a`, Greek `ο` as `o`, etc.
- **Non-NFC unicode** — denormalized representations that look identical to the canonical form

The limitation: by definition, all non-ASCII unicode domains trigger this check.
The fix (discussed below) is script-mixing detection rather than a binary unicode/no-unicode flag.

---

## Detection features worth building

### 1. Confusable character annotation
Unicode publishes an official `confusables.txt` mapping every character to its visually
similar set. Rather than a binary "suspicious/clean" verdict, annotate which specific
characters are confusable and with what. This gives non-expert users an explainable result.

Closest equivalent: the Unicode Confusables utility — manual, no batch support.

### 2. Script-mixing detection
A single DNS label that mixes scripts (Latin + Cyrillic, Latin + Greek) is almost
definitionally an attack. Legitimate IDN domains are single-script. This heuristic
resolves the "all unicode = suspicious" problem and is what Chrome/Firefox do internally
but never surface to users.

### 3. Typosquatting variants
Given an input domain, generate common mutations: character transpositions, missing or
doubled letters, adjacent keyboard keys, common TLD swaps (`.com` → `.co`, `.net`).
`dnstwist` does this as a CLI tool; there is no clean web UI equivalent with batch support.

### 4. RDAP lookup (domain age)
RDAP is the modern, structured-JSON replacement for WHOIS — free, no auth required for
most TLDs. Newly registered + confusable characters is a very high-signal combination.
Nothing currently combines registration data with encoding analysis in one view.

---

## Distribution surfaces

### Surface 1: Browser extension (widest human reach)
WebExtension API covers Chrome, Firefox, and Edge from one codebase. WASM is supported.

- Content script scans all `<a>` hrefs passively, flags where display hostname ≠ ACE form
- Browser action provides interactive analysis for arbitrary input
- Tooltip/badge shows the actual punycode form and the reason for flagging

### Surface 2: MCP server (LLM agent reach — most novel angle)
LLM coding agents (Claude Code, Cursor, Copilot, custom agents) increasingly act on
user-supplied or externally sourced URLs. Prompt injection via malicious links is a real
attack vector. An MCP server exposing a `check_domain` tool lets any agent call it before
fetching an untrusted URL.

Return schema:
```json
{
  "input": "pаypal.com",
  "normalized": "xn--pypal-4ve.com",
  "suspicious": true,
  "reasons": ["mixed_script: Cyrillic U+0430 in Latin label"],
  "confusables": [{ "char": "а", "codepoint": "U+0430", "confusable_with": "a (U+0061)" }]
}
```

There is no established tooling for domain safety checks in agentic workflows. This is
the most underserved niche right now.

### Surface 3: Filter list (passive reach, zero friction)
Hosts-format + AdBlock Plus format, consumed by Pi-hole, AdGuard, uBlock Origin, NextDNS.

Scope: do *not* try to enumerate all homograph permutations of every domain (combinatorial
explosion). Instead:
- Curated confirmed IDN lookalike registrations (these get reported and documented publicly)
- Script-mixing detections surfaced by the pipeline on live DNS queries
- Published as a GitHub repo, auto-updated, URL-importable into NextDNS custom lists

### Surface 4: npm package / WASM module
The shared core that all surfaces consume. Clean TS API, well-defined schema, importable
by any JS/TS project. The punycode logic is already WASM-compilable from the punycoder-online
codebase — this is mostly packaging work.

---

## Technology notes

- **Core logic**: reuse/port the Emscripten WASM from punycoder-online; wrap in a TS API
- **Browser extension**: WebExtension Manifest V3; WASM works in extensions
- **MCP server**: Node.js or Bun, MCP SDK, wraps the npm package
- **Filter list**: static file generation script, hosted on GitHub Pages, standard formats
- **RDAP**: `https://rdap.org/domain/<name>` — no auth, JSON response, rate-limit-friendly

---

## What to skip (at least initially)

- **Standalone native app** — worse distribution than the extension, no agent story
- **Generated homograph blocklist of top-N domains** — combinatorial explosion, maintenance burden,
  superseded by real-time script-mixing detection

---

## Open questions

- How far does the confusables check need to go? Full Unicode confusables.txt is large;
  a curated subset of the highest-risk substitutions may be enough for v1.
- MCP server: local-only (user runs it themselves) or hosted? Hosted raises privacy
  questions since you'd see every domain an agent checks.
- Filter list update cadence — manual curation vs automated pipeline scan?
