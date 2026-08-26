import type { Detector, DetectorFinding, InspectionContext } from "./types.js";

/**
 * `header_shaped_token` (scoring, weight 0.50 -> medium). The path or query
 * carries an HTTP **request-line** or **header field-line** token in its wire
 * form, reached through a percent-encoded wire separator.
 *
 * ── The payload is entirely a URL ───────────────────────────────────────────
 * James Kettle's 2022 response-queue-poisoning work is the strongest case a URL
 * linter gets: the disclosed payload has no body, no header and no method — it
 * is a link. RFC 9112 §3 fixes the request line as
 * `method SP request-target SP HTTP-version CRLF`, and RFC 3986 §2.1 requires
 * an SP inside a URI to be percent-encoded precisely because it is that
 * delimiter. So a request target carrying `%20HTTP/1.1` is a string that reads
 * as one target and, to any component that writes it onto the wire without
 * re-encoding, becomes a target plus a version token plus a new line.
 *
 *   https://example.com/a%20HTTP/1.1              -> was 0.00, zero reasons
 *   https://example.com/?x=Host:%20evil.com       -> was 0.00, zero reasons
 *
 * ── Why `control_char` does not already cover this ──────────────────────────
 * `control_char` (0.60) catches the percent-encoded CR, LF, TAB and NUL forms,
 * and `docs/reason-codes.md` states its exclusion outright: an encoded **space**
 * is not a control character and does not flag. That exclusion is correct for
 * that code and leaves exactly this shape uncovered, because SP is the byte the
 * request-line grammar delimits on. Where an encoded CRLF *is* present the two
 * co-fire, and this code adds what the byte scan cannot say: WHICH header the
 * injected line declares.
 *
 * ── The false positive is the hard part, so the gate is a combination ───────
 * `Host:` is ordinary text. It appears in a docs search, an article slug, an
 * event listing. Firing on the bare token would be a precision disaster, so no
 * arm below fires on one. Every arm requires the token AND a percent-encoded
 * wire separator adjacent to it, and the field-line arm requires a third thing:
 * a value drawn from that field's own value grammar.
 *
 *   1. **Request-line shape** — `%20` or `%09` immediately followed by an
 *      HTTP-version token (`HTTP/1.1`, `HTTP%2f1.0`). RFC 9112 §2.3 fixes the
 *      version token's spelling, and nothing else puts one directly behind an
 *      encoded SP.
 *   2. **Field-line shape** — a field name, a colon (literal or `%3a`), one or
 *      more encoded SP/HTAB, and a value inside that field's grammar: a
 *      host-shaped token for `Host`, digits for `Content-Length`, a registered
 *      transfer coding for `Transfer-Encoding`, `100-continue` for `Expect`.
 *   3. **CRLF-introduced field line** — an encoded CR or LF followed by a field
 *      name and its colon. Here the encoded line break is the second signal, so
 *      the value grammar is not required: an encoded newline sitting directly in
 *      front of a header field name is not ambiguous.
 *
 * The measured effect of the third requirement on arm 2: `?q=Host:` stays quiet
 * (no encoded separator), `?q=Transfer-Encoding%3A+chunked` stays quiet (a form
 * encoder writes `+` for SP, and `+` is not an SP byte outside
 * `application/x-www-form-urlencoded`), and `?title=Expect:%20the%20unexpected`
 * and `?owner=Host:%20John%20Smith` stay quiet because prose is outside the
 * field's value grammar even though the encoded separator is there.
 *
 * ── Weight: 0.50, argued from the table ─────────────────────────────────────
 * Below `control_char` (0.60), which is the same attack with the injected byte
 * itself present in the string — that code needs no token to be sure, and this
 * one is one inference further from the wire. Above `encoding_obfuscation`
 * (0.35) and `idna_protocol_violation` (0.35), which name an encoding step or a
 * protocol violation without naming a mechanism; this names the mechanism and
 * the field. 0.50 is `separator_lookalike`'s weight, its closest peer in kind: a
 * token that misdirects a reader about where a structural boundary falls. It
 * lands `medium` — reviewable, stacking with `control_char` /
 * `encoding_obfuscation` on the full Kettle payload, and not tripping the
 * default `--fail-on high` gate alone, which is the right call while the
 * residual false positives above are only narrowed rather than eliminated. A
 * blocker weight (1.0) is not earned: the encoded SP travels only if something
 * downstream re-emits the target undecoded, and that is a property of one
 * deployment rather than of the string.
 *
 * ── Scope ───────────────────────────────────────────────────────────────────
 * Path and query only. A fragment is stripped before the request target is
 * built, so a header-shaped token there reaches no wire and claiming otherwise
 * would widen the code past what it can settle from the string.
 *
 * Pure, synchronous, no network/fs.
 */

/** RFC 9112 §2.3 — `HTTP-version = HTTP "/" DIGIT "." DIGIT`, behind an encoded SP/HTAB. */
const REQUEST_LINE = /(?:%20|%09)HTTP(?:\/|%2f)\d\.\d/i;

/** An encoded CR or LF, in the single-encoded form that survives a URL. */
const ENCODED_CRLF = "(?:%0d|%0a)";

/** Field names whose wire form is worth naming, each with its own value grammar. */
const HOST_VALUE =
  "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?:(?::|%3a)\\d{1,5})?";
const TRANSFER_CODING = "(?:chunked|compress|deflate|gzip|identity|x-gzip|x-compress)";

const FIELDS: ReadonlyArray<readonly [name: string, value: string, gloss: string]> = [
  ["host", HOST_VALUE, "a host-shaped value — the field that re-targets the request"],
  ["content-length", "\\d+", "a decimal length — the field a desync disagrees about"],
  ["transfer-encoding", TRANSFER_CODING, "a registered transfer coding (RFC 9112 §7)"],
  ["expect", "100-continue", "the only registered expectation (RFC 9110 §10.1.1)"],
];

/** A field name must not be preceded by another field-name character. */
const NAME_LEFT = "(?:^|[^a-z0-9-])";
/** Literal or percent-encoded colon. */
const COLON = "(?::|%3a)";

/** Arm 2 — `Name:` + encoded SP/HTAB + a value inside that field's grammar. */
const FIELD_LINES: ReadonlyArray<readonly [RegExp, string, string]> = FIELDS.map(
  ([name, value, gloss]) =>
    [
      new RegExp(`${NAME_LEFT}${name}${COLON}(?:%20|%09)+${value}(?:$|[^a-z0-9-])`, "i"),
      name,
      gloss,
    ] as const,
);

/** Arm 3 — an encoded CR/LF immediately in front of a field name and its colon. */
const CRLF_FIELD_LINES: ReadonlyArray<readonly [RegExp, string]> = FIELDS.map(
  ([name]) =>
    [new RegExp(`${ENCODED_CRLF}(?:%20|%09)*${name}${COLON}`, "i"), name] as const,
);

/** The wire shapes present in `surface`, most specific first. */
function shapesIn(surface: string): string[] {
  const shapes: string[] = [];

  if (REQUEST_LINE.test(surface)) {
    shapes.push(
      "an encoded space directly in front of an HTTP-version token — the " +
        "request-line shape (RFC 9112 §3)",
    );
  }

  for (const [re, name] of CRLF_FIELD_LINES) {
    if (re.test(surface)) {
      shapes.push(`an encoded line break directly in front of a '${name}:' field name`);
    }
  }

  for (const [re, name, gloss] of FIELD_LINES) {
    if (re.test(surface)) {
      shapes.push(`'${name}:' followed by an encoded space and ${gloss}`);
    }
  }

  return shapes;
}

export const headerShapedToken: Detector = {
  id: "header_shaped_token",
  layer: "lexical",
  run(ctx: InspectionContext): DetectorFinding[] {
    // Path and query only — a fragment is stripped before a request target.
    const surface = ctx.path + (ctx.query === null ? "" : `?${ctx.query}`);
    if (surface === "") return [];
    // Every arm needs a percent-encoded wire separator, so a surface with no
    // escape at all cannot match and is skipped before any regex runs.
    if (!surface.includes("%")) return [];

    const shapes = shapesIn(surface);
    if (shapes.length === 0) return [];

    return [
      {
        code: "header_shaped_token",
        detail:
          `path/query carries an HTTP request-line or header field-line token in wire form: ` +
          `${shapes.join("; ")} — a component that re-emits the request target undecoded ` +
          `writes a second line onto the wire`,
      },
    ];
  },
};
