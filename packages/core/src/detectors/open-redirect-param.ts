import type { Detector } from "./types.js";
import { analyzeHost } from "../parse/psl.js";
import { analyzeIpv4, analyzeIpv6, stripTrailingRootDot } from "../parse/ip.js";
import { boundedDecode, DEFAULT_MAX_DECODE_DEPTH } from "../parse/decode.js";

/**
 * `open_redirect_param`. SCORING, weight 0.4.
 *
 * Flags a query parameter whose NAME is a known redirect parameter and whose
 * decoded VALUE is itself a URL pointing to a DIFFERENT AUTHORITY than the input
 * host — the lexical fingerprint of an open-redirect lure:
 * `https://example.com/login?next=https://evil.com/phish` reads as `example.com`
 * but, when the redirect fires, lands the user on `evil.com`.
 *
 * Pure-lexical, zero network (consistent with all v1 detectors). Two payload
 * shapes are recognized in the decoded value:
 *   - **absolute URL** — scheme + host (`https://evil.com/...`);
 *   - **protocol-relative** — `//evil.com/...`, a classic open-redirect payload
 *     that omits the scheme so naive string checks miss it.
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

/** One decoded `key=value` pair from the raw query, key lower-cased. */
interface QueryPair {
  readonly key: string;
  readonly rawValue: string;
}

/** Split a raw query into pairs, decoding names defensively (a bad name is dropped). */
function queryPairs(query: string, maxDecodeDepth: number): QueryPair[] {
  const pairs: QueryPair[] = [];
  for (const pair of query.split("&")) {
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
  /** Canonical authority identity of the decoded target (see {@link authorityOf}). */
  readonly targetSite: string;
  /** Registrable domain of the target, or null when it is not a public-DNS name. */
  readonly registrableDomain: string | null;
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
    if (host === null) continue;

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
    });
  }

  return payloads;
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

    const [payload] = openRedirectParamPayloads(
      ctx.query,
      inputAuthority.site,
      ctx.runtime.maxDecodeDepth,
    );
    if (payload === undefined) return [];

    const linkHost = ctx.registrableDomain ?? inputAuthority.site;
    const detail =
      payload.registrableDomain !== null
        ? `redirect parameter '${payload.param}' points off-site: its value resolves to ` +
          `'${payload.registrableDomain}', a different registrable domain than the link host ` +
          `'${linkHost}'`
        : `redirect parameter '${payload.param}' points off-site: its value resolves to the ` +
          `host '${payload.targetSite}', which has no registrable domain and is a different ` +
          `authority than the link host '${linkHost}'`;

    return [{ code: "open_redirect_param", detail }];
  },
};
