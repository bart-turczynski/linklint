import { bareSingleLabelHost } from "./raw-parts.js";
import type { RawUrlTokens } from "./raw-tokens.js";
import { isKnownScheme } from "./syntax.js";

/**
 * Naming a parse failure (architecture §1.1, fourth rule, LINK-iuzphbnp).
 *
 * §1.1 settles that "where a `parse_error` is unavoidable, it names what failed
 * rather than standing in for the whole verdict". The serializer has carried
 * the channel for that since the non-string guard landed —
 * `buildInvalidResult`'s `parseErrorDetail` argument, whose fallback is the
 * generic "input is not a parseable URL or hostname" — but only the
 * caller-contract path ever populated it. Every string that failed to parse got
 * the fallback, so `view-source:https://…` and `mhtml:…!x-usc:…` told the
 * caller nothing about which scheme had been read.
 *
 * This module supplies the missing populator, and only for the case where there
 * is a name to give: the input carried a scheme token. That token is the one
 * piece of structure the parser did recover, and reporting it is the difference
 * between "we could not read this" and "we read `ms-appinstaller:` and stopped
 * there". With no scheme there is nothing to name and the fallback stands, so
 * `ht!tp://%%%not a url` and `not a url at all` are byte-identical to before.
 *
 * Scope is deliberately explanation only. Nothing here reaches the reason-code
 * registry, the weight table, or `status`: the affected inputs stay
 * `status: "invalid"` with `score: null` and a single weight-0 `parse_error`,
 * which is the fail-closed shape they already had. §1.1's fourth rule is a
 * reporting obligation and explicitly not a widening of claim (a).
 */

/**
 * Cap on the raw authority region echoed back to the caller. The region is
 * already bounded by the first `/`, `?` or `#`, but nothing bounds it below
 * that, and a reason `detail` is a line of human-readable text rather than an
 * evidence dump — the verbatim `input` echo on the invalid result is where the
 * untruncated string lives.
 */
const MAX_ECHO = 40;

function echo(region: string): string {
  return region.length > MAX_ECHO ? `${region.slice(0, MAX_ECHO)}…` : region;
}

/**
 * Describe why a scheme-bearing input did not parse, or `undefined` when the
 * input carried no scheme and the generic fallback is the honest answer.
 *
 * Two facts go into the message, both read straight off the tokens rather than
 * re-derived:
 *
 *   - WHICH SCHEME, and whether linklint recognizes it. Recognition is a real
 *     distinction to a caller triaging output: an unrecognized scheme is one
 *     linklint has no parse rule for at all, while a recognized one failed on
 *     its body. `view-source:` is the worked case of the second kind — it is in
 *     `KNOWN_SCHEMES`, and `view-source:https://…` still fails, because the
 *     authority region is then the nested `https:` rather than a host.
 *   - WHAT THE AUTHORITY REGION WAS. Empty is its own answer
 *     (`ms-appinstaller:?source=…` has no authority at all); otherwise the
 *     region is quoted so the caller can see the text that was rejected.
 *
 * The scheme is reported lower-cased, matching how `dangerous_scheme` and the
 * policy channel already render one, so two details naming the same scheme
 * agree on its spelling.
 */
export function describeParseFailure(tokens: RawUrlTokens): string | undefined {
  const scheme = tokens.scheme;
  if (scheme === null) return describeSchemelessFailure(tokens);

  const recognition = isKnownScheme(scheme)
    ? "is a scheme linklint recognizes"
    : "is not a scheme linklint recognizes";
  const failure =
    tokens.authority === ""
      ? "no authority follows it"
      : `the authority region '${echo(tokens.authority)}' is not a host`;

  return `scheme '${scheme}:' ${recognition}, and ${failure} — the body after '${scheme}:' was not inspected`;
}

/**
 * The one scheme-less failure with a name to give (LINK-igoxaojd): the input
 * parsed as far as a host, and that host is a single label, which scheme-less
 * input may not be (`isBareSingleLabel` in `raw-parts.ts`). Every other
 * scheme-less failure keeps the generic fallback, as before.
 *
 * The message says what would have made the input acceptable, because the
 * failure is a contract rule rather than a malformation: `localhost` is a fine
 * host behind `http://`.
 */
function describeSchemelessFailure(tokens: RawUrlTokens): string | undefined {
  const host = bareSingleLabelHost(tokens);
  if (host === null) return undefined;
  return `no scheme, and the host '${echo(host)}' is a single label with no dot — input without a scheme must name a dotted host or carry a scheme such as 'http://'; the input was not inspected`;
}
