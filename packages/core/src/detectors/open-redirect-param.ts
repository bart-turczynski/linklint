import type { Detector } from "./types.js";
import { analyzeHost } from "../parse/psl.js";
import { boundedDecode } from "../parse/decode.js";

/**
 * `open_redirect_param`. SCORING, weight 0.4.
 *
 * Flags a query parameter whose NAME is a known redirect parameter and whose
 * decoded VALUE is itself a URL pointing to a DIFFERENT registrable domain than
 * the input host — the lexical fingerprint of an open-redirect lure:
 * `https://example.com/login?next=https://evil.com/phish` reads as `example.com`
 * but, when the redirect fires, lands the user on `evil.com`.
 *
 * Pure-lexical, zero network (consistent with all v1 detectors). Two payload
 * shapes are recognized in the decoded value:
 *   - **absolute URL** — scheme + host (`https://evil.com/...`);
 *   - **protocol-relative** — `//evil.com/...`, a classic open-redirect payload
 *     that omits the scheme so naive string checks miss it.
 *
 * Precision-first (SC-2). Fires ONLY when the decoded value resolves to a host
 * whose registrable domain is non-null AND differs (case-insensitively) from the
 * input's registrable domain. A relative/same-host path (`?next=/dashboard`), a
 * same-registrable-domain target (`?next=https://app.example.com/home`), a
 * non-redirect param carrying a URL (`?ref=https://evil.com`), and a non-URL
 * value (`?url=2`) all stay clean. Parsing is fully defensive: a junk value just
 * yields no finding — the detector never throws.
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

export const openRedirectParam: Detector = {
  id: "open_redirect_param",
  layer: "lexical",
  run(ctx) {
    if (!ctx.query || ctx.registrableDomain === null) return [];

    const inputDomain = ctx.registrableDomainLower!;

    for (const pair of ctx.query.split("&")) {
      if (pair === "") continue;
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      const rawKey = pair.slice(0, eq);
      const rawValue = pair.slice(eq + 1);

      // Decode the name for the match (defensive: a malformed key is just skipped).
      let key: string;
      try {
        key = boundedDecode(rawKey, ctx.runtime.maxDecodeDepth).decoded.toLowerCase();
      } catch {
        continue;
      }
      if (!REDIRECT_PARAMS.has(key)) continue;
      if (rawValue === "") continue;

      // Decode the value through single/double percent-encoding.
      let value: string;
      try {
        value = boundedDecode(rawValue, ctx.runtime.maxDecodeDepth).decoded;
      } catch {
        continue;
      }

      const host = targetHost(value);
      if (host === null) continue;

      let targetDomain: string | null;
      try {
        targetDomain = analyzeHost(host).registrableDomain;
      } catch {
        continue;
      }
      if (targetDomain === null) continue;
      if (targetDomain.toLowerCase() === inputDomain) continue;

      return [
        {
          code: "open_redirect_param",
          detail:
            `redirect parameter '${key}' points off-site: its value resolves to '${targetDomain}', ` +
            `a different registrable domain than the link host '${ctx.registrableDomain}'`,
        },
      ];
    }

    return [];
  },
};
