import { currentPslSnapshot, type PslSnapshot } from "../data/psl-provenance.js";
import { analyzeIpv4, analyzeIpv6, stripTrailingRootDot } from "../parse/ip.js";
import { parse } from "../parse/parse.js";
import { analyzeHost, privateRegistrableDomain } from "../parse/psl.js";
import { toAsciiUnder } from "../unicode/idna.js";

/**
 * URL relationship comparison (LINK-vycgfumd): does one URL address the same
 * origin, or the same site, as another?
 *
 * This is a SECOND question from `inspect()`'s. `inspect()` asks whether a
 * single string is deceptive; this asks how two strings relate. It scores
 * nothing, emits no reason codes, and is ADVISORY — see {@link UrlComparison}.
 *
 * ## Why it is not a caller-side one-liner
 *
 * `ParsedUrl` reports what was *written*, which is what the character-level
 * detectors need. It applies none of the four normalizations a comparison
 * needs, and `packages/core/test/parsed-origin-derivation.test.ts` pins all
 * four as absent:
 *
 *   1. **Default-port elision.** `https://ex.com:443/` reports port `443`;
 *      `https://ex.com/` reports `null`.
 *   2. **Host case folding.** `http://EX.com/` reports host `EX.com`.
 *   3. **Trailing root label.** `https://ex.com./` reports host `ex.com.`.
 *   4. **A-label / U-label equivalence.** `münchen.de` and
 *      `xn--mnchen-3ya.de` are one host written two ways, and NO field of
 *      `ParsedUrl` puts them on the same value — `registrableDomain` differs
 *      too, because tldts is handed the spelling it was given.
 *
 * A comparator that reads `parsed` field-for-field therefore calls
 * `https://ex.com:443/` and `https://ex.com/` different origins. Each
 * normalization below exists to stop exactly that.
 *
 * ## The relationship to the WHATWG URL Standard
 *
 * `sameOrigin` follows the standard's origin comparison — scheme, host and
 * port, with the host put through UTS-46 ToASCII and IP literals canonicalized,
 * which is what makes (2) and (4) fall out rather than being special-cased.
 * There is exactly ONE deliberate divergence, and it is the trailing root
 * label: the standard keeps it, so a browser reads `https://ex.com./` and
 * `https://ex.com/` as two origins, while this comparator reads them as one.
 * That is a considered choice and it is this repository's own position — the
 * `fqdn_root_label` entry in `docs/reason-codes.md` records that the form
 * "resolves identically to the bare form and every URL parser reads it
 * identically", and names host-string comparison downstream as the hazard the
 * reason code exists to warn about. A comparator IS that downstream consumer,
 * so it applies the normalization the reason code asks callers to apply.
 *
 * `sameSite` is schemeLESS: it compares registrable domains only, so
 * `http://ex.com/` and `https://ex.com/` are the same site. Callers wanting the
 * schemeful variant (RFC 6265bis §5.2) can conjoin `left.scheme ===
 * right.scheme` themselves; both fields are on the result for that reason.
 */

/**
 * A three-state answer, because two states cannot carry what is known here.
 *
 * The distinction that forces it: `data:text/html,x`, `file:///etc/passwd` and
 * `about:blank` are DETERMINATELY not-same-origin — the standard gives each
 * parse a fresh opaque origin, and an opaque origin is not equal to any origin
 * including itself, so two parses of the identical `data:` string are still two
 * origins. That is a fact, not an absence of one, and collapsing it into the
 * same value as "the input did not parse" would tell a caller "unknown" about
 * something the standard settles. So:
 *
 * - `"same"` — the two URLs are established to relate.
 * - `"different"` — the two URLs are established NOT to relate. Opaque origins
 *   land here.
 * - `"undetermined"` — this comparator could not tell. Reached only when an
 *   input did not parse, was not a string, or carries a host that UTS-46
 *   rejects, so no canonical form exists to compare.
 *
 * Read `"different"` as evidence and `"undetermined"` as its absence. In
 * particular `!== "same"` is not a safe substitute for `=== "different"`.
 */
export type UrlRelation = "same" | "different" | "undetermined";

/**
 * What kind of origin one side has, which is what decides whether a comparison
 * against it can conclude anything.
 *
 * - `"tuple"` — a scheme with a tuple origin (`http`, `https`, `ws`, `wss`,
 *   `ftp`) and a host that canonicalized. Comparable.
 * - `"opaque"` — parsed, but the origin is opaque: any other scheme (`data:`,
 *   `about:`, `javascript:`, `mailto:`), a `file:` URL, or a tuple-origin
 *   scheme written with no host. Comparable, and the answer is always
 *   `"different"`.
 * - `"undetermined"` — the input did not parse, was not a string, its host was
 *   rejected by UTS-46 so it has no canonical form, or it wrote no scheme at
 *   all. A bare authority (`ex.com/a`) is the last case: it has a host and
 *   therefore a site, but an origin only relative to a base URL this comparator
 *   was not given. (A scheme-RELATIVE reference, `//ex.com/a`, does not reach
 *   this branch: linklint's parser rejects it outright and `inspect()` reports
 *   `status: "invalid"`, so it lands in the first case above.)
 *
 * `file:` is `"opaque"` per the standard, which leaves file origins
 * implementation-defined; implementations that grant same-origin to sibling
 * file URLs exist, and this comparator does not model any of them.
 */
export type OriginKind = "tuple" | "opaque" | "undetermined";

/** One side of a {@link UrlComparison}: the canonical view it was compared on. */
export interface ComparedUrl {
  /** The input verbatim when it was a string; `null` when it was not. */
  input: string | null;
  /** Lower-cased scheme without its colon, or `null` when none was written. */
  scheme: string | null;
  /** Which origin rule applies to this side. See {@link OriginKind}. */
  originKind: OriginKind;
  /**
   * The canonical comparison host: UTS-46 ToASCII for a domain (so case and the
   * A-label/U-label choice are gone), the RFC 5952 / dotted-quad canonical form
   * for an IP literal, and a single trailing root label removed before either.
   * `null` for a hostless input and for one whose host UTS-46 rejects.
   */
  host: string | null;
  /**
   * The port after default-port elision: `null` when the URL wrote no port, or
   * wrote the scheme's own default. A port outside `0`–`65535` is not repaired
   * upstream and does not reach here; such an input fails to parse.
   */
  port: number | null;
  /**
   * Registrable domain under the PSL's PRIVATE-inclusive view, so tenants of a
   * multi-tenant platform stay distinct. Falls back to {@link ComparedUrl.host}
   * when the host has no registrable domain under that view — an IP literal, or
   * a suffix the list does not carry (`localhost`) — which is RFC 6265bis's own
   * rule and keeps two such hosts from comparing equal through a shared `null`.
   */
  site: string | null;
  /**
   * The same value under the ICANN-only view — the view every `InspectResult`
   * already reports as `parsed.registrableDomain`, and the one architecture
   * §6.1's documented tradeoff binds the detectors to. Two tenants of one
   * PRIVATE-section platform agree here and differ on {@link ComparedUrl.site}.
   */
  siteIcann: string | null;
}

/**
 * The result of {@link compareUrls}.
 *
 * **ADVISORY.** It reports a relationship, not a permission. It is not an
 * authorization decision, it is not a substitute for the origin check a
 * security boundary performs itself, and a `"same"` answer says the two strings
 * address one origin — not that either is safe to fetch. `inspect()` is what
 * has an opinion about a URL's honesty; this has none.
 *
 * Both site answers are computed from the PSL snapshot bundled in the pinned
 * `tldts`, whose provenance travels on {@link UrlComparison.pslSnapshot} so a
 * caller can see which trust boundary produced them.
 */
export interface UrlComparison {
  /** Do the two URLs have the same origin? See {@link UrlRelation}. */
  sameOrigin: UrlRelation;
  /**
   * Do the two URLs have the same site under the PRIVATE-inclusive PSL view?
   * This is the answer that separates `alice.github.io` from
   * `mallory.github.io`, which the ICANN-only view cannot.
   */
  sameSite: UrlRelation;
  /**
   * Do the two URLs have the same site under the ICANN-only view — the view
   * `parsed.registrableDomain` reports? Kept alongside `sameSite` because the
   * two disagree exactly on PRIVATE-section platforms, and which one a caller
   * wants depends on whether they treat a platform's tenants as one party.
   */
  sameSiteIcann: UrlRelation;
  /** The canonical view the left input was compared on. */
  left: ComparedUrl;
  /** The canonical view the right input was compared on. */
  right: ComparedUrl;
  /**
   * Provenance of the PSL snapshot both site answers were computed against.
   *
   * `stale` is ONE-DIRECTIONAL and its `false` is unreachable today: it comes
   * from `pslOutdated()`, which returns `false` only for a `dateKind` of
   * `"exact"`, and the shipped `PSL_PROVENANCE` record carries
   * `"release-proxy"` (architecture §6.1, LINK-elzuacby). The pinned date is a
   * packaging-release proxy that bounds the snapshot's age from below, so this
   * field can prove staleness and cannot prove freshness. Test `=== true` to
   * act on proven staleness; read `null` as "unknown", which is what it is, and
   * do not read `!== true` as a claim that these site answers are current.
   */
  pslSnapshot: PslSnapshot;
}

/** Schemes the WHATWG URL Standard gives a tuple origin. `file` is not one. */
const TUPLE_ORIGIN_SCHEMES = new Set(["http", "https", "ws", "wss", "ftp"]);

/** Default port per tuple-origin scheme, elided from the comparison tuple. */
const DEFAULT_PORTS: Record<string, number> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21,
};

/** The side used when an input never became a URL at all. */
function undeterminedSide(input: string | null): ComparedUrl {
  return {
    input,
    scheme: null,
    originKind: "undetermined",
    host: null,
    port: null,
    site: null,
    siteIcann: null,
  };
}

/**
 * Canonical comparison form of a host, or `null` when none exists.
 *
 * The root label goes first, because neither UTS-46 nor the IP analyzers treat
 * it as a no-op; then an IP literal takes its canonical rendering (so
 * `0x7f000001` and `127.0.0.1` meet, and so do `::1` and `0:0:0:0:0:0:0:1`);
 * then a domain goes through UTS-46 ToASCII, which folds case and reconciles
 * the A-label and U-label spellings in one step.
 *
 * `toAsciiUnder(host, false)` is used rather than `toAscii()` on purpose:
 * `toAscii()` falls back to its input on failure, which would silently compare
 * two hosts UTS-46 rejects on their raw spelling. A `null` here becomes
 * `"undetermined"`, which is the honest answer.
 */
function canonicalHost(host: string, isIp: boolean): string | null {
  if (host === "") return null;
  const bare = stripTrailingRootDot(host);
  if (bare === "") return null;

  if (isIp) {
    const v4 = analyzeIpv4(bare);
    if (v4 !== null) return v4.canonical;
    const v6 = analyzeIpv6(bare);
    if (v6 !== null) return v6.canonical;
    return bare.toLowerCase();
  }

  return toAsciiUnder(bare, false);
}

/** Build the canonical view of one input. */
function describe(input: unknown): ComparedUrl {
  if (typeof input !== "string") return undeterminedSide(null);

  const ctx = parse(input);
  if (ctx === null) return undeterminedSide(input);

  const scheme = ctx.scheme;
  const host = canonicalHost(ctx.host, ctx.isIp);

  // No host means no tuple origin, whatever the scheme claimed. A rejected host
  // is a different case entirely and is separated below.
  if (host === null) {
    const rejected = ctx.host !== "" && stripTrailingRootDot(ctx.host) !== "";
    return {
      input,
      scheme,
      originKind: rejected ? "undetermined" : "opaque",
      host: null,
      port: null,
      site: null,
      siteIcann: null,
    };
  }

  // No scheme (a bare authority, `ex.com/a`) means no origin without a base
  // URL, which is a gap in what was given rather than a settled answer — so
  // `"undetermined"`, not `"opaque"`. The site question is unaffected: the host
  // is right there, and a caller asking "same site?" about two bare authorities
  // is asking something answerable.
  const originKind: OriginKind =
    scheme === null ? "undetermined" : TUPLE_ORIGIN_SCHEMES.has(scheme) ? "tuple" : "opaque";
  const port = ctx.port !== null && ctx.port === DEFAULT_PORTS[scheme ?? ""] ? null : ctx.port;

  // RFC 6265bis: a host with no registrable domain is its own site. Falling
  // back to the host keeps two such hosts from meeting through a shared `null`.
  const site = ctx.isIp ? host : (privateRegistrableDomain(host) ?? host);
  const siteIcann = ctx.isIp ? host : (analyzeHost(host).registrableDomain ?? host);

  return { input, scheme, originKind, host, port, site, siteIcann };
}

/** Origin relation between two canonical views. */
function relateOrigin(left: ComparedUrl, right: ComparedUrl): UrlRelation {
  if (left.originKind === "undetermined" || right.originKind === "undetermined") {
    return "undetermined";
  }
  // An opaque origin equals nothing, itself included.
  if (left.originKind === "opaque" || right.originKind === "opaque") return "different";
  return left.scheme === right.scheme && left.host === right.host && left.port === right.port
    ? "same"
    : "different";
}

/**
 * A side's site is unknown only when nothing about its host could be
 * established. A HOSTLESS input is a different case: it has no site, and that
 * is settled rather than unknown — the same reasoning as an opaque origin.
 */
function siteUndetermined(side: ComparedUrl): boolean {
  return side.originKind === "undetermined" && side.host === null;
}

/** Site relation on one of the two views. */
function relateSite(
  left: ComparedUrl,
  right: ComparedUrl,
  pick: (side: ComparedUrl) => string | null,
): UrlRelation {
  if (siteUndetermined(left) || siteUndetermined(right)) return "undetermined";
  const l = pick(left);
  const r = pick(right);
  if (l === null || r === null) return "different";
  return l === r ? "same" : "different";
}

/**
 * Compare two URLs and report how they relate: same origin, same site under the
 * PRIVATE-inclusive PSL view, and same site under the ICANN-only view.
 *
 * Pure, synchronous, offline, and total — it performs no I/O and returns a
 * result for any argument, a non-string one included, which lands as
 * `"undetermined"` rather than a thrown `TypeError`. It follows `inspect()`'s
 * discipline here for the same reason `inspect()` has it: a comparator that
 * throws in a caller's error path fails open.
 *
 * @param left One URL, as a string.
 * @param right The other URL, as a string.
 * @returns An advisory {@link UrlComparison}; see that type before acting on it.
 *
 * @example
 * ```ts
 * compareUrls("https://ex.com:443/a", "https://EX.com./b").sameOrigin; // "same"
 * compareUrls("https://alice.github.io/", "https://mallory.github.io/");
 * // → sameSite: "different", sameSiteIcann: "same"
 * compareUrls("data:text/html,x", "data:text/html,x").sameOrigin; // "different"
 * ```
 */
export function compareUrls(left: string, right: string): UrlComparison {
  const a = describe(left);
  const b = describe(right);

  return {
    sameOrigin: relateOrigin(a, b),
    sameSite: relateSite(a, b, (side) => side.site),
    sameSiteIcann: relateSite(a, b, (side) => side.siteIcann),
    left: a,
    right: b,
    pslSnapshot: currentPslSnapshot(),
  };
}
