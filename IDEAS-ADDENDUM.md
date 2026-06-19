# urlic — feature addendum

> Companion to [IDEAS.md](./IDEAS.md). That brief nails the homograph/IDN insight and the
> distribution surfaces. This addendum expands the *detection surface* outward from "the
> hostname" to "the whole URL, where it goes, and who's behind it" — the rest of what an
> all-encompassing URL security tool has to cover.
>
> Guiding principle inherited from the original: **explainable over binary.** Every signal
> below should emit a named reason, not just bump a score. The same principle that makes the
> confusables annotation good ("Cyrillic U+0430 in a Latin label") applies to everything here.

---

## 0. Mental model: three layers of a URL

The original brief operates on **Layer 1** (the hostname). A complete tool reasons across all three:

| Layer | Question | Example threats |
|-------|----------|-----------------|
| **1. Lexical** | Does the URL string *look* deceptive on its face? | homographs, userinfo spoofing, IP obfuscation, deceptive subdomains, dangerous TLDs |
| **2. Resolution** | Where does it actually *go*? | redirect chains, link shorteners, open redirects, cloaking |
| **3. Reputation / infrastructure** | What's *known* about the destination? | Safe Browsing hits, domain age, TLS/CT history, hosting ASN, DNS posture |

Layer 1 is offline and instant (the existing core). Layer 2 and 3 need network and introduce
privacy/latency tradeoffs — they should be **opt-in, clearly labeled, and gracefully degradable**
so the tool still gives a verdict with no network.

---

## 1. Full-URL lexical analysis (extends Layer 1 beyond the hostname)

The punycode core only sees the hostname. But most of the cheapest, highest-volume phishing
tricks live elsewhere in the URL string. These are all **offline, deterministic, zero-dependency**
checks — the same class as script-mixing.

### 1.1 Userinfo / authority deception
`https://www.paypal.com@evil.com/login` — everything before the `@` is userinfo; the real host is
`evil.com`. Flag any URL containing userinfo, and surface the *actual* effective host prominently.
This is one of the oldest tricks and still works on humans.

### 1.2 IP-address obfuscation
Hosts can be written as decimal (`http://2130706433`), octal (`http://0177.0.0.1`), hex
(`http://0x7f000001`), or mixed/dotless forms — all resolving to `127.0.0.1`. Detect non-standard
host encodings and render the canonical dotted-quad / IPv6 form. Raw IP literals as the host (no
domain at all) are themselves a mild signal for consumer-facing links.

### 1.3 Deceptive subdomain / label structure
`paypal.com.account-verify.ru` — the brand is buried in a subdomain; the registrable domain is
`account-verify.ru`. Parse with the **Public Suffix List** to identify the true registrable domain
(eTLD+1) and show it distinctly from the full host. Flag: brand keyword appearing anywhere left of
the registrable domain, excessive label depth, and label counts well above the norm.

### 1.4 Dangerous / file-extension-confusable TLDs
The `.zip` and `.mov` TLDs collide with file extensions — `setup.zip` is a valid *domain*. Maintain
a watchlist of (a) extension-confusable TLDs and (b) TLDs with disproportionately high abuse rates
(historically `.tk`, `.gq`, `.cf`, `.xyz`, etc., plus current data). Treat as a contextual signal,
not a verdict.

### 1.5 Bidi / RTL override and control characters
U+202E (RIGHT-TO-LIGHT OVERRIDE) and friends can reverse displayed text so `gnp.exe` shows as
`exe.png`, and can scramble displayed URLs/paths. Detect bidi-control, zero-width, and other
non-printing control characters **anywhere in the URL** (not just the host — the path and query
matter too).

### 1.6 Percent-encoding & obfuscation in path/query
Double-encoding (`%252F`), encoded structural characters (encoded `@`, `/`, `?`), and gratuitous
encoding of ASCII letters are evasion tells. Decode, then re-check the decoded form through the
whole pipeline (recursive normalization, bounded depth).

### 1.7 Non-HTTP and embedded-payload schemes
Flag/annotate `javascript:`, `data:`, `blob:`, `file:`, and `vbscript:` URLs, and `data:` URIs that
embed HTML/SVG (XSS and credential-harvest vectors). For agent contexts (MCP) this is critical — an
agent should never auto-fetch a `javascript:` "URL."

### 1.8 Homographs *in the path*, not just the host
The confusables engine already exists; run it on path segments and query values too. A legit host
with a homograph-laden path can still be a cloaked redirect or tracking trap.

**Closest equivalent for §1 as a whole:** scattered across `urlscan.io`, browser internals, and
one-off regex blog posts. No single explainable client-side library bundles all of it.

---

## 2. Resolution analysis (Layer 2 — where does it actually go?)

### 2.1 Redirect-chain expansion
Follow HTTP 3xx, `<meta http-equiv="refresh">`, and (optionally, sandboxed) JS redirects to the
final landing URL, then **run every hop through the Layer 1 pipeline**. Surface the full chain.
A clean-looking shortlink that lands on a homograph domain is the whole point.

### 2.2 Link-shortener / wrapper expansion
Recognize known shortener and click-tracker domains (bit.ly, t.co, lnkd.in, safelinks, proofpoint
URL-defense wrappers, etc.) and expand or unwrap them. Unwrapping vendor "protection" wrappers is
itself useful — they hide the real destination from the user.

### 2.3 Open-redirect detection
Parameters like `?url=`, `?next=`, `?redirect=`, `?return=`, `?dest=` carrying an absolute URL to a
*different* host are an open-redirect fingerprint (legit-domain → attacker payload). Flag when a
trusted-looking host carries a cross-origin redirect parameter.

### 2.4 Cloaking / divergence hints
Full cloaking detection is hard, but cheap signals exist: destination differs by User-Agent or by
`Referer`, or the page is gated behind a CAPTCHA/JS challenge that a plain fetch can't pass. Report
as "could not fully resolve" rather than a false clean.

---

## 3. Reputation & threat-intelligence (Layer 3)

These are **network, opt-in, and privacy-sensitive**. Architect them behind a common interface with
per-source enable flags so users (and the MCP host) choose their trust/latency/privacy tradeoff.

### 3.1 Blocklist / feed lookups
- **Google Safe Browsing** (Update API — uses local hash-prefix sets, privacy-preserving by design)
- **URLhaus** (abuse.ch) — malware URLs, free, bulk-downloadable
- **PhishTank / OpenPhish** — phishing feeds
- **VirusTotal** — multi-engine aggregate (rate-limited, API key)

Prefer the **local-bloom-filter / hash-prefix** model (download the set, query offline) over
phone-home-per-URL wherever a source supports it — this dovetails with the privacy-preserving
lookups in §6.

### 3.2 Domain age & registration (extends the RDAP idea)
The brief already calls out RDAP. Expand: registrar, registrant country, registration *and last-update*
timestamps, and **nameserver / parked-page detection**. "Registered 3 days ago + DV cert issued
yesterday + brand keyword" is the canonical phishing fingerprint.

### 3.3 TLS & Certificate Transparency
- Inspect the live cert: issuer, validity window, SAN list, age.
- Query **CT logs (crt.sh)**: a brand keyword appearing in newly-issued certs is an early
  phishing-prep signal *before* the site is even weaponized — and powers proactive monitoring (§7).
- Free DV cert is not itself bad (it's the norm now), but *new DV cert + new domain + brand match* is.

### 3.4 DNS & hosting posture
A/AAAA records, MX presence (no mail = likely not a real org), hosting **ASN and geo**, nameservers,
DNSSEC status, and fast-flux indicators (rapidly rotating A records, many IPs across ASNs).

---

## 4. Brand & typosquat intelligence (extends §3 of the brief)

The original typosquatting idea (`dnstwist`-style mutations) is generation-side. Add the
*classification* side — given an unknown domain, how close is it to a known brand?

- **Combosquatting**: `paypal-secure.com`, `login-paypal.com` — brand keyword + additive token. Far
  more common than character typos and not caught by edit-distance alone.
- **Edit-distance to a brand watchlist**: Levenshtein/Damerau against a configurable list of
  protected brands; report the nearest match and distance.
- **Soundsquatting / homophones**: `whatsapp` → `whatsupp`, `getflix`. Optional, phonetic.
- **Keyword-stuffing score**: density of security-bait tokens (`secure`, `verify`, `account`,
  `update`, `signin`, `wallet`) in the host/path.
- **Bitsquatting** (single-bit-flip neighbors) — niche, for completeness.

This is the natural complement to §1.3: §1.3 finds the brand *inside* a hostile domain; §4 measures
*similarity* of the whole domain to a brand.

---

## 5. Content / page-level signals (optional, heavily sandboxed)

Deepest layer, highest cost, most privacy-sensitive — gate firmly behind explicit opt-in, and never
on the passive content-script path of the extension. Useful for an analyst/CLI "deep scan" mode.

- **Favicon hashing**: hash the favicon and compare to known-brand favicons — phishing kits reuse the
  real brand's favicon on a hostile domain. (mmh3 favicon hash is a known IOC technique.)
- **Login-form detection**: a password field whose form `action` posts cross-origin, or a login form
  on a domain with no brand relationship, is high-signal.
- **Title / brand-string mismatch**: page `<title>` claims a brand the domain doesn't match.
- **Visual / DOM similarity** (advanced): screenshot or structural comparison to the legit site.

Render these as enrichment, with a loud "this fetched and executed remote content" disclosure.

---

## 6. Scoring, explainability & privacy

### 6.1 Weighted, explainable risk model
Replace any binary verdict with a **transparent additive/weighted score** that emits the contributing
reasons and a severity (`info` / `low` / `medium` / `high` / `critical`) plus a confidence. Each
detector contributes a named, documented reason code (e.g. `userinfo_present`, `mixed_script`,
`recently_registered`, `open_redirect_param`). The MCP/JSON schema in the brief should carry this
structured reason list, not a single boolean — so an agent can apply its own policy threshold.

Extend the brief's MCP return schema along these lines:
```json
{
  "input": "https://paypal.com@xn--pypal-4ve.ru/login?next=http://evil.com",
  "effective_host": "xn--pypal-4ve.ru",
  "registrable_domain": "xn--pypal-4ve.ru",
  "score": 0.94,
  "severity": "critical",
  "confidence": 0.9,
  "reasons": [
    { "code": "userinfo_present",   "layer": "lexical",    "detail": "authority hidden behind 'paypal.com@'" },
    { "code": "mixed_script",       "layer": "lexical",    "detail": "Cyrillic U+0430 in Latin label" },
    { "code": "open_redirect_param","layer": "resolution", "detail": "next= points to cross-origin http://evil.com" },
    { "code": "recently_registered","layer": "reputation", "detail": "RDAP creation date 3 days ago" }
  ],
  "checks_run": ["lexical"],
  "checks_skipped": ["reputation: offline mode"]
}
```
`checks_run` / `checks_skipped` matters: callers must know whether a "clean" result means *checked
and clean* or *not checked*.

### 6.2 Privacy-preserving lookups
Any phone-home check should default to **k-anonymity hash-prefix** queries (the HIBP / Safe Browsing
model: send a hash prefix, filter the returned bucket locally) rather than sending the full URL. This
directly answers the brief's open question about the hosted MCP server seeing every domain — with
prefix queries, it doesn't have to.

### 6.3 Offline-first degradation
Layer 1 always runs with zero network. Layers 2–3 degrade to "skipped" with a clear marker. The tool
must be honest about what it did and didn't check.

---

## 7. Monitoring mode (new capability, not just one-shot checks)

The brief is request/response. A security tool also *watches*. Given a brand watchlist:

- Stream **CT logs** for newly-issued certs containing brand keywords or homograph variants.
- Periodically re-check generated typosquat permutations (§3 of brief) for *new registrations* via
  RDAP/DNS.
- Emit alerts (webhook, email, Slack/Discord) and auto-feed confirmed hits into the filter list
  (Surface 3 in the brief).

This turns the filter-list surface from manually curated into a **continuously-fed pipeline**, which
answers the brief's open question on update cadence.

---

## 8. Additional distribution surfaces (extends the brief's four)

The brief covers extension, MCP, filter list, and npm/WASM. Rounding out the coverage:

### Surface 5: CLI
The natural home for batch and CI use. `urlic check <url>`, `urlic batch urls.csv`,
`--offline`, `--json`, non-zero exit on `severity >= high`. This is what `dnstwist` users already
reach for, and the brief notes there's no clean equivalent with batch support.

### Surface 6: GitHub Action / CI gate
Scan links in PR diffs, Markdown docs, dependency manifests, and changelogs; fail or comment on
suspicious URLs. Catches malicious links in docs/READMEs and supply-chain-adjacent link tampering.

### Surface 7: ChatOps bot (Slack / Discord / Teams)
Paste a URL, get an inline explainable verdict. Low-friction reach into the exact place suspicious
links get shared ("is this link safe?").

### Surface 8: Email / gateway integration
A milter / API that scores links in inbound mail. Heavier, but it's where phishing actually lands.

### Surface 9: Hosted REST API + serverless
A thin HTTP wrapper over the core for non-JS consumers, with the privacy-preserving prefix model so
the hosted endpoint never needs the full URL for blocklist checks.

### Surface 10: Non-JS bindings
The WASM core (Surface 4) can back Python and Rust bindings — security teams live in Python.

---

## 9. Operational concerns (cross-cutting)

- **Caching** of RDAP/DNS/CT/reputation results with sane TTLs — these are slow and rate-limited.
- **Rate-limit & backoff** handling per third-party source; never let one slow source block a verdict.
- **False-positive feedback loop**: user-reportable allowlist, and a way to mark "this is fine" that
  feeds tuning. The brief's core limitation ("all non-ASCII = suspicious") generalizes — every
  heuristic needs an escape hatch.
- **Versioned reason codes & data sets**: confusables.txt, PSL, abused-TLD list, brand watchlist all
  drift; pin versions and surface which version produced a verdict (reproducibility).
- **Test corpus**: a labeled set of known-good and known-bad URLs (PhishTank/OpenPhish positives +
  Tranco top-sites negatives) to measure precision/recall as detectors are added.

---

## 10. Suggested prioritization

Keeps the project shippable rather than boiling the ocean.

1. **v1 — pure-lexical core (offline):** existing punycode/confusables/script-mixing **+ all of §1**
   (userinfo, IP obfuscation, PSL/eTLD+1, dangerous TLDs, bidi/control chars, encoding, path
   homographs) **+ §6.1 explainable scoring.** Zero network, instant, the differentiated core. Ships
   the npm/WASM module and the MCP server immediately.
2. **v2 — resolution (§2) + RDAP/age (§3.2):** redirect expansion, shortener unwrap, open-redirect,
   domain age. The "newly registered + confusable" combo the brief calls out as high-signal.
3. **v3 — reputation feeds (§3.1) + privacy-preserving lookups (§6.2)** and the CLI / CI surfaces.
4. **v4 — TLS/CT (§3.3) + monitoring mode (§7)**, feeding the filter list automatically.
5. **Later / specialist:** content-level signals (§5), email-gateway and ChatOps surfaces.

---

## 11. New open questions

- **Brand watchlist provenance**: ship a default top-brands list, let users extend it, or both? A
  bundled list is a maintenance and liability surface.
- **Where does network live for the extension?** Layer 2–3 checks in a browser extension mean either
  the extension phones home or it calls a backend — both have privacy implications the passive
  content-script scan does not.
- **Scoring weights**: hand-tuned and transparent (explainable, but arbitrary) vs learned from the
  labeled corpus (better calibrated, but a black box that undercuts the "explainable" thesis)?
- **How much resolution is safe to do automatically?** Following redirects *fetches* attacker-controlled
  URLs. In an MCP/agent context that may be exactly what you're trying to avoid — resolution should
  probably be explicitly requested, not default.
