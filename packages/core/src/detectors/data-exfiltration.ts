import type { Detector, DetectorFinding } from "./types.js";
import { boundedDecode } from "../parse/decode.js";

/**
 * `data_exfiltration`. Agent-gated. Detects exfil-marker query parameter names
 * and overlong opaque values. Design rationale and examples live in
 * docs/reason-codes.md.
 */

/**
 * Query parameter NAMES that signal data being smuggled out, lowercase. Compared
 * case-insensitively against the EXACT decoded parameter name (set membership,
 * never a substring scan) to stay conservative.
 *
 * `data` was dropped from this set (LINK-uyoocslu). It is an ordinary English
 * word and one of the most common parameter names on the web — Microsoft's link
 * rewriter puts `&data=05%7C01` into every URL it touches, and this repository's
 * own online fixtures carry the shape — so it flagged
 * `https://blog.example.com/download?data=report2024` at 0.30/medium under agent
 * mode on the name alone. The other five are coined or repurposed terms that do
 * not appear as ordinary parameter names, which is the property that makes a
 * marker set a marker set rather than a vocabulary. An actual dump under a
 * `data=` name is still reached by the overlong-opaque-token branch below, which
 * keys on the VALUE and so does not depend on what the parameter is called.
 */
const EXFIL_MARKER_PARAMS: ReadonlySet<string> = new Set([
  "exfil",
  "beacon",
  "dump",
  "leak",
  "payload",
]);

/**
 * Decoded-value length at/above which a value is "abnormally long". Length is
 * necessary but not sufficient; the opaqueness gate must also pass.
 */
const OVERLONG_VALUE_LEN = 200;

/** Minimum alphanumeric density for a value to read as an opaque blob. */
const MIN_ALNUM_DENSITY = 0.9;

/**
 * Signed JWTs are legitimate long opaque values in OAuth/OIDC URLs; leave those
 * to the credential-harvesting detector instead of keying on bare token length.
 */
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

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
        if (
          value !== null &&
          value.length >= OVERLONG_VALUE_LEN &&
          !JWT_SHAPE.test(value) &&
          isOpaqueBlob(value)
        ) {
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
