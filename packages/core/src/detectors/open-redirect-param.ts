import type { Detector } from "./types.js";
import { analyzeHost } from "../parse/psl.js";
import { analyzeIpv4, analyzeIpv6, stripTrailingRootDot } from "../parse/ip.js";
import { boundedDecode, DEFAULT_MAX_DECODE_DEPTH } from "../parse/decode.js";

/**
 * `open_redirect_param`. SCORING, weight 0.4.
 *
 * Flags a redirect parameter whose NAME is a known redirect parameter and whose
 * decoded VALUE is itself a URL pointing to a DIFFERENT AUTHORITY than the input
 * host — the lexical fingerprint of an open-redirect lure:
 * `https://example.com/login?next=https://evil.com/phish` reads as `example.com`
 * but, when the redirect fires, lands the user on `evil.com`.
 *
 * Pure-lexical, zero network (consistent with all v1 detectors). Three payload
 * shapes are recognized in the decoded value:
 *   - **absolute URL** — scheme + host (`https://evil.com/...`);
 *   - **protocol-relative** — `//evil.com/...`, a classic open-redirect payload
 *     that omits the scheme so naive string checks miss it;
 *   - **hostless dangerous scheme** — `javascript:alert(1)`, `data:text/html,…`
 *     (see {@link DANGEROUS_PAYLOAD_SCHEMES}).
 *
 * ## The hostless dangerous-scheme payload (`LINK-txgqerim`)
 *
 * The first two shapes both route through {@link targetHost}, which needs an
 * authority. A `javascript:` payload has none, so the highest-severity payload
 * the registry knows about was the one shape this detector could not see:
 * `javascript:alert(1)` reads `0.90`/`critical` as an INPUT and read `0.00` the
 * moment it was wrapped in `?next=`. `docs/architecture.md` §5 puts both codes in
 * the same **Dangerous payloads** family, and a redirect parameter carrying
 * `javascript:` is the paradigm case of it.
 *
 * The claim is still claim-(a) structural, and it is the FIRST of §1.1's three
 * forms rather than the divergence one: a parameter whose NAME declares where the
 * navigation goes next carries a value that is not a location at all but
 * executable content. Nothing about that needs to know what the site does.
 *
 * **Reported as `open_redirect_param` at its own weight `0.4`, NOT as
 * `dangerous_scheme` at `0.9`.** That is a constraint, not a preference:
 * `detectors/checks.ts` declares `emits: ["open_redirect_param"]` for this check
 * and `test/checks-registry.test.ts` asserts that no reason code is emitted by two
 * descriptors, so the payload case cannot be routed through the `dangerous_scheme`
 * check; and a NEW code would force a `SCHEMA_VERSION` bump. The honest cost is
 * recorded rather than hidden: a wrapped `javascript:` payload is reported one
 * band lower than the same bytes standing alone. Reporting it at `0.4` is strictly
 * better than the `0.00` it read before, and re-grading it is a weights decision
 * for whoever owns `scoring/weights.ts`.
 *
 * {@link DANGEROUS_PAYLOAD_SCHEMES} duplicates FR-D-11's set for the same reason —
 * `dangerous-scheme.ts` keeps its copy module-private. The duplication is guarded:
 * `test/open-redirect-param-dangerous-payload.test.ts` reads the literal out of
 * `dangerous-scheme.ts` and drives both sides of the biconditional from it, so the
 * two copies cannot drift silently.
 *
 * Only the HOSTLESS spelling was missing. `?next=file://evil.com/x` and
 * `?next=javascript://evil.com/%0aalert(1)` already fired, because both parse to
 * an authority that diverges from the input's — that path is untouched and is
 * still tried first.
 *
 * ## Two input surfaces: query AND fragment (`LINK-txgqerim`)
 *
 * The premise below — "the string presents one authority and the payload names
 * another" — is a property of the payload, not of the delimiter in front of it,
 * and nothing in §1.1, `docs/guarantees.md` or `docs/reason-codes.md` ever drew
 * a boundary at `?`. The detector originally read `ctx.query` alone, so
 * `…/login#next=https://evil.com/phish` scored `0.00` while its `?` twin scored
 * `0.40`. That gap is exactly the DOM-based open redirect: `location.hash` read
 * into `window.location` by client-side code. The fragment is never sent to the
 * server, which is the whole reason the variant exists — and it is already
 * carried through `parse/context.ts` and already read by `encoding-obfuscation`,
 * `low-byte-truncation` and `percent-encoding-malformed`.
 *
 * SAME reason code, SAME weight, WIDER input surface. A distinct code would
 * force a `SCHEMA_VERSION` bump for no semantic gain: the claim is identical and
 * a consumer that wants to know which surface carried it can read the detail.
 *
 * {@link fragmentQueryLike} is what makes the fragment comparable. A fragment is
 * not required to be a query string, and hash routers write both spellings:
 * `#next=…` (bare pairs) and `#/route?next=…` (a route with its own query). The
 * text after the FIRST `?` is taken when there is one, else the whole fragment;
 * the two surfaces are then scanned by the same {@link openRedirectParamPayloads}
 * with no second grammar to keep in step. Each surface is scanned independently,
 * so the RFC 6749 exemption below is decided from the pairs on the SAME surface
 * — a `client_id` in the query cannot silence a `redirect_uri` in the fragment,
 * and the query path is byte-for-byte what it was.
 *
 * ## A third surface: the Android intent URI's fallback extra (`LINK-mdqykmiz`)
 *
 * `intent://legit-bank.co.uk/x#Intent;scheme=https;S.browser_fallback_url=javascript%3Aalert(1);end`
 * read `0.00`/`info` with zero reasons, while the identical `javascript:` bytes
 * read `0.90`/`critical` standing alone. The ticket guessed the fix was one entry
 * in {@link REDIRECT_PARAMS}; it is not, and the reason is measurable. An intent
 * URI separates its extras with `;`, not `&`, so {@link queryPairs} reads the
 * whole fragment as ONE pair whose key is `intent;scheme` — the fallback name
 * never becomes a key at all, whatever the list says. The `S.` typed-extra prefix
 * is a second reason the bare name would not match.
 *
 * So the grammar is what had to be read, and it is read only where the string
 * DECLARES it: {@link intentExtras} requires the fragment to be
 * `Intent;…;end`, which is the exact shape AOSP's `Intent.parseUri` accepts. A
 * fragment that merely contains a `;` is untouched, and every non-intent input is
 * byte-for-byte what it was — the query and fragment surfaces above are not
 * modified.
 *
 * **On this surface only the HOSTLESS dangerous-scheme shape fires, not the
 * divergence shape**, and that narrowing is the §1.1 test applied rather than a
 * tuning choice. A `browser_fallback_url` naming a different site is what the
 * mechanism is FOR — it is where the browser goes when the app is not installed,
 * and the documented Android pattern points it at the app's Play Store listing,
 * which is a different authority by construction. The string declares its own
 * type and the declaration HOLDS: nothing is hidden, no two readers disagree, so
 * there is no claim-(a) finding — the same reasoning that exempts an RFC 6749
 * authorize request below. What does NOT hold is a declared *fallback URL* whose
 * value is not a location at all but executable content; that is §1.1's first
 * form and it is the shape the ticket filed.
 *
 * This was measured, not assumed. The wider variant — `;` split plus the name in
 * {@link REDIRECT_PARAMS}, so divergence fires too — was implemented, run, and
 * discarded: it produced **zero** verdict change across all 1 506 corpus verdicts
 * (the corpus carries no `intent://` row, so it cannot discriminate here) while
 * firing `0.40` on
 * `intent://example.com/deep#Intent;scheme=https;package=com.example.app;S.browser_fallback_url=…play.google.com…;end`,
 * the canonical benign app-handoff link. The false-positive class the ticket
 * flagged as unquantified is therefore real and is avoided by construction rather
 * than by an allowlist of "real" fallback hosts, which §1.1 forbids outright.
 *
 * SAME reason code, SAME weight, one more input surface — no new code and no
 * `SCHEMA_VERSION` bump, for the same reason the fragment surface needed neither.
 *
 * ## The divergence gate is over AUTHORITY, not over registrable domain
 *
 * The premise is claim-(a) structural: the string presents one authority and the
 * payload names another. Registrable domain is the right identity for a
 * public-DNS host and the WRONG identity for everything else, because
 * `analyzeHost` returns `null` for an IP literal and for a non-PSL name. Gating
 * on a non-null registrable domain therefore exempted *every* IP-literal target:
 * `http://169.254.169.254/` scores 1.00/critical as an input under agentMode and
 * scored 0.00 the moment it was wrapped in `?url=` — the SSRF-to-IMDS pivot,
 * through a detector that is not agent-gated (`LINK-cvcjgewz`).
 *
 * {@link authorityOf} replaces that clause with a total identity function: the
 * registrable domain when the host has one, otherwise the CANONICAL address for
 * an IP literal (so `2130706433`, `0x7f.0.0.1` and `127.0.0.1` are one
 * authority, and `::ffff:7f00:1` matches its own spelling variants), otherwise
 * the bare host itself (`localhost`, `intranet`). Divergence is then decidable
 * for every host, including on the INPUT side — an IP-literal input used to
 * short-circuit the whole scan and can no longer hide an off-site payload.
 *
 * ## Why `redirect_uri` + `client_id` is exempt (and why it is not a list)
 *
 * A cross-registrable-domain handoff is not an anomaly in an OAuth 2.0
 * authorization request — it is the entire protocol. RFC 6749 §4.1.1 defines
 * `redirect_uri` only inside that request and requires `client_id` in every
 * instance of it, so the pair is the standards-shaped signature of a delegated
 * authorization handoff, readable from the string alone. Under §1.1 the string
 * then declares its own type and the declaration HOLDS: nothing is hidden and no
 * two readers disagree, so there is no claim-(a) finding to make.
 *
 * The alternatives were evaluated and rejected:
 *   - **An IdP allowlist** — a curated watchlist deciding which hosts are
 *     "really" identity providers. That is claim (b) wearing claim (a)'s
 *     clothes and is forbidden outright by §1.1's name-never-create rule.
 *   - **Also requiring `response_type`** — RFC-conformant, but 5 of the 15 real
 *     authorize shapes measured for this change (GitHub, Slack, Shopify,
 *     Facebook, Meta-style dialogs) omit it, so a third of the false-positive
 *     mass would survive. Measurement beat conformance.
 *   - **Requiring the target to be same-site** — inverts the protocol; the
 *     redirect target is by construction a different site from the IdP.
 *
 * The exemption is deliberately narrow in three ways. It is keyed to the exact
 * RFC spelling `redirect_uri`, so `redirect_url`, `next`, `url` and every other
 * member of {@link REDIRECT_PARAMS} are untouched and a `client_id` bolted onto
 * one of them suppresses nothing. It is per-parameter, so a URL carrying both an
 * authorize request and a second off-site payload still fires on the second. And
 * it applies ONLY when the target is a public-DNS authority: an authorize
 * request whose `redirect_uri` is an IP literal — including RFC 8252 §7.3
 * loopback, which no gate can distinguish from an SSRF pivot on the string alone
 * — is not exempt.
 *
 * ## Stated non-goal
 *
 * A consent-phishing authorize URL (attacker-registered `client_id`, an
 * attacker-controlled but syntactically ordinary `redirect_uri`) is BYTE-SHAPED
 * IDENTICALLY to a legitimate one. Separating them needs to know which client is
 * malicious and which redirect URI the provider registered — claim (b), and not
 * derivable from the string. That shape is out of scope, not missed.
 *
 * Precision-first (SC-2). A relative/same-host path (`?next=/dashboard`), a
 * same-authority target (`?next=https://app.example.com/home`,
 * `http://127.0.0.1:3000/?next=http://127.0.0.1:3000/home`), a non-redirect
 * param carrying a URL (`?ref=https://evil.com`), and a non-URL value (`?url=2`)
 * all stay clean. Parsing is fully defensive: a junk value just yields no
 * finding — the detector never throws.
 */

/** Known redirect parameter names (compared case-insensitively). */
const REDIRECT_PARAMS = new Set([
  "next",
  "url",
  "redirect",
  "redirect_uri",
  "redirect_url",
  "dest",
  "destination",
  "return",
  "returnurl",
  "continue",
  "u",
  "goto",
  "target",
]);

/**
 * The RFC 6749 §4.1.1 spelling. Only this exact parameter name can carry the
 * authorization-request exemption; `redirect_url` and the rest are generic.
 */
const OAUTH_REDIRECT_PARAM = "redirect_uri";

/** Required in every RFC 6749 authorization request; the marker for the exemption. */
const OAUTH_CLIENT_ID_PARAM = "client_id";

/**
 * FR-D-11's executable/embedding schemes, duplicated from `dangerous-scheme.ts`
 * because that module keeps its copy private and `checks.ts` will not let this
 * check emit the `dangerous_scheme` code. Kept in step by
 * `test/open-redirect-param-dangerous-payload.test.ts`, which reads the literal
 * out of `dangerous-scheme.ts`.
 */
const DANGEROUS_PAYLOAD_SCHEMES = new Set(["javascript", "data", "blob", "file", "vbscript"]);

/**
 * The dangerous scheme a HOSTLESS payload declares, lower-cased, or null.
 *
 * Only reached after {@link targetHost} has declined, so a spelling that DOES
 * carry an authority (`javascript://evil.com/%0aalert(1)`, `file://evil.com/x`)
 * has already been handled by the divergence path and never arrives here.
 */
function dangerousPayloadScheme(value: string): string | null {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(value.trim());
  if (m === null) return null;
  const scheme = (m[1] as string).toLowerCase();
  return DANGEROUS_PAYLOAD_SCHEMES.has(scheme) ? scheme : null;
}

/**
 * Extract the target host from a decoded redirect value, if it looks like a URL
 * pointing at a host. Returns null for relative paths and non-URL values.
 */
function targetHost(value: string): string | null {
  const v = value.trim();
  if (v === "") return null;

  // Protocol-relative: //host/... (classic open-redirect payload).
  if (v.startsWith("//") && !v.startsWith("///")) {
    try {
      const u = new URL("https:" + v);
      return u.hostname || null;
    } catch {
      return null;
    }
  }

  // Absolute URL with an explicit scheme + authority: scheme://host/...
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) {
    try {
      const u = new URL(v);
      return u.hostname || null;
    } catch {
      return null;
    }
  }

  return null;
}

/** The identity a host is compared by, plus its registrable domain when it has one. */
interface Authority {
  /**
   * Canonical, lower-cased identity: the registrable domain for a public-DNS
   * host, the canonical address for an IP literal, else the bare host.
   */
  readonly site: string;
  /** Registrable domain, or null when the host is not a public-DNS name. */
  readonly registrableDomain: string | null;
}

/**
 * Total authority identity for a host. Never throws and never returns null for a
 * non-empty host — that totality is the fix for the IP-literal exemption.
 *
 * IPv6 is tried before IPv4 because `analyzeIpv4` accepts a bare integer, and the
 * bracket form arrives from `URL.hostname` while `InspectionContext.host` does
 * not carry brackets; both are normalized here so the two sides compare.
 */
function authorityOf(host: string): Authority | null {
  let h = stripTrailingRootDot(host.trim()).toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h === "") return null;

  let registrableDomain: string | null = null;
  try {
    registrableDomain = analyzeHost(h).registrableDomain;
  } catch {
    registrableDomain = null;
  }
  if (registrableDomain !== null) {
    return { site: registrableDomain.toLowerCase(), registrableDomain };
  }

  const v6 = h.includes(":") ? analyzeIpv6(h) : null;
  if (v6) return { site: v6.canonical, registrableDomain: null };

  const v4 = analyzeIpv4(h);
  if (v4) return { site: v4.canonical, registrableDomain: null };

  return { site: h, registrableDomain: null };
}

/**
 * The query-like slice of a fragment, or null when there is nothing to scan.
 *
 * A fragment is opaque by RFC 3986 — it has no defined internal grammar — but the
 * two spellings client-side routers actually produce are both readable as
 * `application/x-www-form-urlencoded` pairs once the route prefix is removed:
 *
 *   - `#next=https://evil.com/phish`        → `next=https://evil.com/phish`
 *   - `#/checkout?next=https://evil.com/x`  → `next=https://evil.com/x`
 *
 * Splitting on the FIRST `?` is what separates them: everything after it when a
 * `?` is present, the whole fragment otherwise. A fragment with no `=` in it
 * yields no pairs downstream and is therefore inert, so no extra guard is needed.
 */
function fragmentQueryLike(fragment: string | null): string | null {
  if (fragment === null || fragment === "") return null;
  const q = fragment.indexOf("?");
  return q === -1 ? fragment : fragment.slice(q + 1);
}

/**
 * The Android intent URI fragment grammar: `#Intent;<extra>;<extra>;end`. This is
 * the exact spelling AOSP's `Intent.parseUri` accepts — the literal `Intent;`
 * opener and the `end` terminator, both case-sensitive — so a fragment that
 * merely contains a `;` is not treated as one, and neither is a truncated intent
 * block that no reader would parse.
 */
const INTENT_FRAGMENT = /^Intent;.*;end$/;

/**
 * The fallback-URL extra, in the two spellings that reach a reader: the bare name
 * and the `S.` string-typed-extra prefix Android writes in practice. Keys are
 * compared lower-cased, as in {@link REDIRECT_PARAMS}. Like that list, this one
 * only NAMES which token counts — the finding comes from the payload.
 */
const INTENT_FALLBACK_PARAMS = new Set(["browser_fallback_url", "s.browser_fallback_url"]);

/**
 * The `;`-separated extras of an Android intent URI fragment, or null when the
 * fragment does not declare itself one.
 */
function intentExtras(fragment: string | null): string | null {
  if (fragment === null) return null;
  const f = fragment.trim();
  return INTENT_FRAGMENT.test(f) ? f : null;
}

/** One decoded `key=value` pair from the raw query, key lower-cased. */
interface QueryPair {
  readonly key: string;
  readonly rawValue: string;
}

/**
 * Split a raw parameter string into pairs, decoding names defensively (a bad name
 * is dropped).
 *
 * The separator is a parameter because the Android intent surface uses `;` where
 * the query and fragment surfaces use `&`; the pair grammar either side of it is
 * identical, so there is no second splitter to keep in step.
 */
function queryPairs(query: string, maxDecodeDepth: number, separator = "&"): QueryPair[] {
  const pairs: QueryPair[] = [];
  for (const pair of query.split(separator)) {
    if (pair === "") continue;
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    try {
      pairs.push({
        key: boundedDecode(pair.slice(0, eq), maxDecodeDepth).decoded.toLowerCase(),
        rawValue: pair.slice(eq + 1),
      });
    } catch {
      continue;
    }
  }
  return pairs;
}

/**
 * A decoded redirect-parameter payload that points off-site: a known redirect
 * parameter whose decoded value resolves to an authority that differs from the
 * input's. This is the exact lexical premise of `open_redirect_param`.
 */
export interface OpenRedirectPayload {
  /** Lowercased matched redirect-parameter name (`next`, `url`, …). */
  readonly param: string;
  /**
   * Canonical authority identity of the decoded target (see {@link authorityOf}),
   * or `'<scheme>:'` when {@link dangerousScheme} is set and there is no authority.
   */
  readonly targetSite: string;
  /** Registrable domain of the target, or null when it is not a public-DNS name. */
  readonly registrableDomain: string | null;
  /**
   * Lower-cased scheme when the payload is a HOSTLESS dangerous-scheme URL
   * (`javascript:`, `data:`, …), else null. Such a payload names no destination at
   * all, so the divergence gate does not apply to it and neither does the RFC 6749
   * exemption, which is defined only over public-DNS targets.
   */
  readonly dangerousScheme: string | null;
}

/**
 * A payload target that has a registrable domain — the subset the Layer 2
 * resolution enricher can correlate an observed landing against, since that
 * comparison is registrable-domain-based.
 */
export interface OpenRedirectTarget {
  /** Lowercased matched redirect-parameter name (`next`, `url`, …). */
  readonly param: string;
  /** Registrable domain of the decoded target, in the case `analyzeHost` returned. */
  readonly registrableDomain: string;
}

/**
 * Extract every off-site open-redirect payload from a raw query string.
 *
 * The single source of truth for the `open_redirect_param` premise. Pure and
 * zero-network — it only decodes and classifies the value already present in the
 * URL.
 *
 * @param query The raw query string without a leading `?` (`ParsedUrl.query`).
 * @param inputSiteLower The input host's authority identity, lower-cased.
 * @param maxDecodeDepth Bounded percent-decode depth (defaults to the core cap).
 */
export function openRedirectParamPayloads(
  query: string | null,
  inputSiteLower: string | null,
  maxDecodeDepth: number = DEFAULT_MAX_DECODE_DEPTH,
): OpenRedirectPayload[] {
  if (!query || inputSiteLower === null || inputSiteLower === "") return [];

  const pairs = queryPairs(query, maxDecodeDepth);
  // RFC 6749 §4.1.1 marker: `client_id` is required in every authorization request.
  const isAuthorizationRequest = pairs.some(
    (p) => p.key === OAUTH_CLIENT_ID_PARAM && p.rawValue !== "",
  );

  const payloads: OpenRedirectPayload[] = [];
  for (const { key, rawValue } of pairs) {
    if (!REDIRECT_PARAMS.has(key)) continue;
    if (rawValue === "") continue;

    // Decode the value through single/double percent-encoding.
    let value: string;
    try {
      value = boundedDecode(rawValue, maxDecodeDepth).decoded;
    } catch {
      continue;
    }

    const host = targetHost(value);
    if (host === null) {
      // No authority to diverge from — but a hostless `javascript:`/`data:` value
      // is not a destination at all, which is the first of §1.1's three forms.
      const scheme = dangerousPayloadScheme(value);
      if (scheme === null) continue;
      payloads.push({
        param: key,
        targetSite: `${scheme}:`,
        registrableDomain: null,
        dangerousScheme: scheme,
      });
      continue;
    }

    const authority = authorityOf(host);
    if (authority === null) continue;
    if (authority.site === inputSiteLower) continue;

    // OAuth 2.0 authorization request: the cross-site handoff is the protocol,
    // not a deception. Narrow by construction — exact RFC spelling, a `client_id`
    // in the same query, and a public-DNS target only, so an authorize request
    // pointing at an IP literal stays in scope.
    if (
      key === OAUTH_REDIRECT_PARAM &&
      isAuthorizationRequest &&
      authority.registrableDomain !== null
    ) {
      continue;
    }

    payloads.push({
      param: key,
      targetSite: authority.site,
      registrableDomain: authority.registrableDomain,
      dangerousScheme: null,
    });
  }

  return payloads;
}

/**
 * The executable payload declared as an Android intent URI's browser fallback, or
 * null.
 *
 * Deliberately narrower than {@link openRedirectParamPayloads}: only the HOSTLESS
 * dangerous-scheme shape is a finding here. A fallback naming another site is the
 * mechanism working as documented — see the `LINK-mdqykmiz` section above — so the
 * divergence gate carries no information on this surface and is not applied.
 *
 * Pure, bounded and defensive: a junk fragment yields null and nothing throws.
 */
function intentFallbackPayload(
  fragment: string | null,
  maxDecodeDepth: number,
): OpenRedirectPayload | null {
  const extras = intentExtras(fragment);
  if (extras === null) return null;

  for (const { key, rawValue } of queryPairs(extras, maxDecodeDepth, ";")) {
    if (!INTENT_FALLBACK_PARAMS.has(key)) continue;
    if (rawValue === "") continue;

    let value: string;
    try {
      value = boundedDecode(rawValue, maxDecodeDepth).decoded;
    } catch {
      continue;
    }

    const scheme = dangerousPayloadScheme(value);
    if (scheme === null) continue;
    return {
      param: key,
      targetSite: `${scheme}:`,
      registrableDomain: null,
      dangerousScheme: scheme,
    };
  }
  return null;
}

/**
 * Off-site payload targets that carry a registrable domain.
 *
 * Consumed by the Layer 2 resolution enricher to check whether an OBSERVED chain
 * actually landed on one of them (`LINK-rupjqxus`). That correlation compares
 * registrable domains, so payloads without one (an IP-literal target) are not
 * correlatable and are excluded here even though the lexical detector reports
 * them.
 *
 * @param query The raw query string without a leading `?` (`ParsedUrl.query`).
 * @param inputRegistrableDomainLower The input host's registrable domain, lower-cased.
 * @param maxDecodeDepth Bounded percent-decode depth (defaults to the core cap).
 */
export function openRedirectParamTargets(
  query: string | null,
  inputRegistrableDomainLower: string | null,
  maxDecodeDepth: number = DEFAULT_MAX_DECODE_DEPTH,
): OpenRedirectTarget[] {
  if (inputRegistrableDomainLower === null) return [];

  const targets: OpenRedirectTarget[] = [];
  for (const payload of openRedirectParamPayloads(
    query,
    inputRegistrableDomainLower,
    maxDecodeDepth,
  )) {
    if (payload.registrableDomain === null) continue;
    targets.push({ param: payload.param, registrableDomain: payload.registrableDomain });
  }
  return targets;
}

export const openRedirectParam: Detector = {
  id: "open_redirect_param",
  layer: "lexical",
  run(ctx) {
    const inputAuthority = authorityOf(ctx.host);
    if (inputAuthority === null) return [];

    // Query first, then fragment: the query is the commoner spelling, and the
    // first payload found is the one reported (the code is emitted at most once).
    const surfaces: ReadonlyArray<readonly [string, string | null]> = [
      ["redirect parameter", ctx.query],
      ["fragment redirect parameter", fragmentQueryLike(ctx.fragment)],
    ];

    const found: Array<readonly [string, OpenRedirectPayload]> = [];
    for (const [label, text] of surfaces) {
      const [payload] = openRedirectParamPayloads(
        text,
        inputAuthority.site,
        ctx.runtime.maxDecodeDepth,
      );
      if (payload !== undefined) found.push([label, payload]);
    }
    // The Android intent fallback extra is scanned LAST and on its own terms, so
    // every non-intent input is byte-for-byte what it was (`LINK-mdqykmiz`).
    if (found.length === 0) {
      const payload = intentFallbackPayload(ctx.fragment, ctx.runtime.maxDecodeDepth);
      if (payload !== null) found.push(["intent fallback parameter", payload]);
    }

    for (const [label, payload] of found) {
      const linkHost = ctx.registrableDomain ?? inputAuthority.site;
      let detail: string;
      if (payload.dangerousScheme !== null) {
        detail =
          `${label} '${payload.param}' carries an executable payload rather than a ` +
          `destination: its value is a hostless '${payload.dangerousScheme}:' URL, a scheme ` +
          `that can execute or embed content, on a link that reads as '${linkHost}'`;
      } else if (payload.registrableDomain !== null) {
        detail =
          `${label} '${payload.param}' points off-site: its value resolves to ` +
          `'${payload.registrableDomain}', a different registrable domain than the link host ` +
          `'${linkHost}'`;
      } else {
        detail =
          `${label} '${payload.param}' points off-site: its value resolves to the ` +
          `host '${payload.targetSite}', which has no registrable domain and is a different ` +
          `authority than the link host '${linkHost}'`;
      }

      return [{ code: "open_redirect_param", detail }];
    }

    return [];
  },
};
