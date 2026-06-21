import type { Detector, DetectorFinding } from "./types.js";
import { boundedDecode } from "../parse/decode.js";

/**
 * `data_exfiltration`. SCORING, weight 0.3. **AGENT-GATED** — emits only when
 * `InspectOptions.agentMode` is true (wired via `agentGated: true` in checks.ts).
 * Like the other gated detectors, this targets the LLM-agent / tool-use context:
 * an agent that follows (or is induced to construct) a link carrying a smuggled
 * data payload is the party at risk of exfiltrating context, secrets, or
 * conversation contents to an attacker-controlled endpoint via a query string.
 *
 * ── What fires ──────────────────────────────────────────────────────────────
 * Two query-parameter SHAPES, both purely lexical (zero network):
 *
 *   - **exfil-marker parameter NAME** — a parameter whose decoded NAME is an
 *     exfiltration marker (`data`, `exfil`, `beacon`, `dump`, `leak`, `payload`)
 *     carrying a NON-empty value. The canonical beaconing shape
 *     (`?beacon=<base64 blob>`, `?exfil=...`).
 *   - **overlong opaque token value** — ANY parameter whose value is an
 *     abnormally long, opaque, high-density blob (the shape of a stolen-data
 *     payload smuggled out as `?token=<2KB base64>`, `?d=<hex dump>`). Length
 *     threshold AND an opaqueness check, so ordinary long query values do not
 *     trip it.
 *
 * This SEPARATE reason code stacks naturally with the other detectors — the
 * scoring is a probabilistic OR, so reasons compound on their own. The detector
 * emits only its own code; it never special-cases stacking.
 *
 * ── Precision / calibration: the overlong-token threshold + opaqueness ───────
 * Long query values exist in perfectly legitimate flows: search strings, signed
 * JWTs, URL-encoded redirect targets, CSP report blobs. To avoid tripping on
 * those:
 *   • **length threshold = 200 chars** (decoded value length). A conservative
 *     floor: a 200+ char opaque token is well beyond a typical search box,
 *     short id, or page param, but a multi-KB stolen-data dump clears it easily.
 *     A signed JWT can reach this length too — which is exactly why length alone
 *     is not enough and the opaqueness gate below is also required.
 *   • **opaqueness gate** — the value must read as an opaque blob, not natural
 *     language: it has NO spaces (decoded `+`/`%20` count as spaces), it is drawn
 *     almost entirely from the base64/hex/url-safe alphabet
 *     (`A-Za-z0-9 + / - _ . = ~`), and its alphanumeric DENSITY is high (>= 0.9).
 *     A natural-language `q=` search string has spaces and punctuation and fails
 *     the gate; a base64/hex dump passes. The check is a single bounded pass over
 *     the value (no regex backtracking), well within the <5ms budget.
 *
 * ── Why weight 0.3 (lower band) ─────────────────────────────────────────────
 * "Medium priority" per PRD. Calibrated in the lower band, just below
 * credential_harvesting (0.35) and the encoding_obfuscation band: an exfil-shaped
 * query is a real but not decisive standalone signal (legitimate apps DO post
 * long opaque tokens and have params named `data`), so it corroborates / stacks
 * rather than flagging alone.
 *
 * Reuses `ctx.query` and the bounded decoder; it never re-parses the URL and
 * never throws (an undecodable name/value just yields no finding).
 */

/**
 * Query parameter NAMES that signal data being smuggled out, lowercase. Compared
 * case-insensitively against the EXACT decoded parameter name (set membership,
 * never a substring scan) to stay conservative.
 */
const EXFIL_MARKER_PARAMS: ReadonlySet<string> = new Set([
  "data",
  "exfil",
  "beacon",
  "dump",
  "leak",
  "payload",
]);

/**
 * Decoded-value length at/above which a value is "abnormally long" and a
 * candidate stolen-data payload. Conservative floor (see file header): well past
 * ordinary search/id/page params, but easily cleared by a multi-KB dump. Length
 * is necessary but NOT sufficient — the opaqueness gate must also pass.
 */
const OVERLONG_VALUE_LEN = 200;

/** Minimum alphanumeric density for a value to read as an opaque blob. */
const MIN_ALNUM_DENSITY = 0.9;

/**
 * Single bounded pass: is `value` an opaque, high-density base64/hex/url-safe
 * blob (no spaces, almost all alphanumeric, drawn from the opaque alphabet)?
 * Natural-language strings (spaces, rich punctuation) fail; encoded blobs pass.
 */
function isOpaqueBlob(value: string): boolean {
  let alnum = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const isDigit = c >= 48 && c <= 57; // 0-9
    const isUpper = c >= 65 && c <= 90; // A-Z
    const isLower = c >= 97 && c <= 122; // a-z
    if (isDigit || isUpper || isLower) {
      alnum++;
      continue;
    }
    // A space (raw, or a decoded `+`) immediately disqualifies — natural text.
    if (c === 32) return false;
    // Allowed non-alphanumeric blob characters: + / - _ . = ~
    const isOpaquePunct =
      c === 43 /* + */ ||
      c === 47 /* / */ ||
      c === 45 /* - */ ||
      c === 95 /* _ */ ||
      c === 46 /* . */ ||
      c === 61 /* = */ ||
      c === 126 /* ~ */;
    if (!isOpaquePunct) return false; // any other character ⇒ not an opaque blob
  }
  return alnum / value.length >= MIN_ALNUM_DENSITY;
}

/** Decode a raw query token, mapping `+` to space first (form-encoding). Returns
 *  null if it cannot decode. */
function decodeToken(raw: string, maxDepth: number): string | null {
  try {
    return boundedDecode(raw.replace(/\+/g, " "), maxDepth).decoded;
  } catch {
    return null;
  }
}

export const dataExfiltration: Detector = {
  id: "data_exfiltration",
  layer: "lexical",
  agentGated: true,
  run(ctx): DetectorFinding[] {
    if (!ctx.query) return [];

    for (const pair of ctx.query.split("&")) {
      if (pair === "") continue;
      const eq = pair.indexOf("=");
      const rawKey = eq === -1 ? pair : pair.slice(0, eq);
      const rawValue = eq === -1 ? "" : pair.slice(eq + 1);

      // 1. Exfil-marker parameter NAME carrying a non-empty value.
      if (rawValue !== "") {
        const key = decodeToken(rawKey, ctx.runtime.maxDecodeDepth);
        if (key !== null && EXFIL_MARKER_PARAMS.has(key.toLowerCase())) {
          return [
            {
              code: "data_exfiltration",
              detail:
                `query parameter '${key.toLowerCase()}' is a data-exfiltration marker ` +
                `carrying a value — the shape of context/secrets being smuggled out in the URL`,
            },
          ];
        }
      }

      // 2. Overlong opaque token VALUE (any parameter name).
      if (rawValue !== "") {
        const value = decodeToken(rawValue, ctx.runtime.maxDecodeDepth);
        if (value !== null && value.length >= OVERLONG_VALUE_LEN && isOpaqueBlob(value)) {
          const name = decodeToken(rawKey, ctx.runtime.maxDecodeDepth)?.toLowerCase() ?? rawKey;
          return [
            {
              code: "data_exfiltration",
              detail:
                `query parameter '${name}' carries an abnormally long (${value.length}-char) ` +
                `opaque base64/hex-style token — the shape of a stolen-data payload smuggled ` +
                `out in the URL`,
            },
          ];
        }
      }
    }

    return [];
  },
};
