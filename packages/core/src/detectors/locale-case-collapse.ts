import type { Detector, DetectorFinding } from "./types.js";
import { toAscii } from "../unicode/idna.js";
import { isExactBrandDomain } from "./brand-utils.js";

/**
 * `locale_case_ambiguity` / `brand_locale_collapse`. A SINGLE detector emitting
 * TWO codes, strongest first (it reports one finding per input).
 *
 * Flags the ASCII-COLLAPSE direction of the locale-tailored case mapping class
 * (the "Turkish-I problem"): a host carrying a character that a `tr`/`az`
 * lowercase erases into a plain ASCII letter, so a validator running under an
 * ambient Turkish locale reads a *different, fully ASCII* domain than the one
 * the resolver reaches.
 *
 *   https://tİktok.com/
 *     validator, ambient tr locale:  'tiktok.com'          <- exact brand match
 *     resolver, UTS-46 (mandatory):  'xn--tiktok-qyd.com'  <- the attacker
 *
 * Nothing non-ASCII survives the validator's view, so every downstream
 * "is this an IDN?" heuristic sees a clean ASCII brand and waves it through.
 * That is a validate-then-transform split in the attacker's favor, and it is the
 * same shape as the Java `toLowerCase()` / .NET `ToLower()` allowlist-bypass
 * CVEs. Full analysis: docs/locale-case-mapping.md.
 *
 * ── Why this is a separate axis from `idna_mapping_ambiguity` ──────────────
 * That detector flags hosts that DIFFERENT IDNA STANDARDS map differently. This
 * one flags hosts that the SAME standard maps differently than an ambient
 * LOCALE does. Identical validate-then-transform shape, different axis.
 *
 * ── Why the opposite direction is not detected here ────────────────────────
 * The mirror case ('WIKI.com' --tr lowercase--> the attacker's 'wıkı.com') is
 * deliberately out of scope. A detector on the input would have to trigger on
 * "host contains I", which fires on essentially every uppercase host. It also
 * needs no detector: U+0131 (ı) IS in the UTS-39 confusable table, so the domain
 * an attacker must actually register already scores 1.0 via
 * `homograph_latin_skeleton`. See docs/locale-case-mapping.md §4.
 *
 * ── Precision (SC-2, precision=1 discipline) ───────────────────────────────
 * The base annotation is informational (weight 0). A lone `İ` is ordinary
 * Turkish orthography — `İstanbul` is a real word and `İ`-bearing IDNs are
 * legitimately registrable — so the base signal must never raise severity on its
 * own. The value is in the escalation: when the collapsed form equals a
 * watchlist brand domain EXACTLY, byte for byte, it becomes
 * `brand_locale_collapse`. That is the same evidentiary bar as
 * `homograph_skeleton_collision` ("skeleton equals a known brand exactly"), and
 * carries the same weight.
 *
 * This ships the scoring escalation that `idna_mapping_ambiguity` still only
 * describes, for the locale axis.
 */

/**
 * The tr/az lowercase tailoring, implemented explicitly rather than via
 * `toLocaleLowerCase("tr")`.
 *
 * Two reasons, both load-bearing:
 *  1. `toLocaleLowerCase` reads ICU data, so its availability and behavior vary
 *     with the runtime's ICU build (`small-icu` Node, browsers, workers).
 *     linklint's verdict must not depend on the host build — a detector that
 *     silently stops firing on some runtimes is worse than no detector.
 *  2. It keeps the locale-independence drift-lock in
 *     packages/core/test/locale-independence.test.ts unconditional: NO source
 *     file calls a locale-sensitive API, including this one.
 *
 * Only the rules that can affect the collapse are modeled, in order
 * (Unicode SpecialCasing.txt, the `tr`/`az` conditional mappings):
 *
 *   I + U+0307  ->  i    (the After_I rule: the combining dot is absorbed)
 *   U+0130 (İ)  ->  i    (the precomposed form of the same thing)
 *   I           ->  ı    (U+0131 — the mirror direction, modeled so a plain
 *                         ASCII `I` does NOT masquerade as a collapse)
 *
 * Everything else takes the locale-independent default mapping. Lithuanian is
 * deliberately absent: its tailoring only ADDS combining dots, so it can never
 * produce an ASCII collapse (verified by exhaustive codepoint sweep — U+0130 is
 * the ONLY codepoint in Unicode whose tailored lowercase is pure ASCII while its
 * default lowercase is not).
 */
export function turkishLowercase(host: string): string {
  let out = "";
  for (let i = 0; i < host.length; i++) {
    const ch = host[i]!;
    if (ch === "I") {
      // After_I: an immediately following COMBINING DOT ABOVE is absorbed.
      if (host[i + 1] === "̇") {
        out += "i";
        i++;
      } else {
        out += "ı"; // dotless ı — NOT an ASCII collapse
      }
    } else if (ch === "İ") {
      out += "i";
    } else {
      // Locale-independent by ECMA-262 (Unicode Default Case Conversion).
      out += ch.toLowerCase();
    }
  }
  return out;
}

/** True if every code unit of `s` is in the ASCII range (U+0000–U+007F). */
function isPureAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}

export const localeCaseCollapse: Detector = {
  id: "locale_case_collapse",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    if (ctx.isIp) return [];

    // The RAW host, deliberately: `ctx.registrableDomain` has already been
    // default-lowercased, which turns `I` + U+0307 into `i` + U+0307 and so
    // destroys the After_I context before we can see it. A tr-locale validator
    // lowercases the URL as written, so that is what we must model.
    const host = ctx.host;
    if (host === "" || isPureAscii(host)) return [];

    const collapsed = turkishLowercase(host);
    // The collapse must be TOTAL. A host that still carries a non-ASCII
    // codepoint after the tailored mapping is an ordinary IDN: the validator
    // sees something visibly international and the ASCII-disguise premise fails.
    if (!isPureAscii(collapsed)) return [];

    // What the resolver actually reaches, per the URL Standard.
    const resolved = toAscii(host);
    if (collapsed === resolved) return []; // no divergence — nothing to warn about

    // Re-derive the registrable domain of the collapsed form. The tailored
    // mapping rewrites characters within labels and never adds, removes, or
    // reorders a `.`, so the collapsed registrable domain is exactly the same
    // trailing label count — no second PSL lookup needed.
    const rdLabelCount = ctx.registrableDomain?.split(".").length ?? 0;
    const collapsedRd =
      rdLabelCount > 0 ? collapsed.split(".").slice(-rdLabelCount).join(".") : collapsed;

    if (isExactBrandDomain(collapsedRd)) {
      return [
        {
          code: "brand_locale_collapse",
          detail:
            `registrable domain '${ctx.registrableDomain}' collapses to exactly the brand ` +
            `domain '${collapsedRd}' under a Turkish/Azeri lowercase, while the URL Standard ` +
            `resolves it to '${resolved}' — a validator running under a Turkish locale would ` +
            "approve it as the brand and the request would still reach a different domain",
        },
      ];
    }

    return [
      {
        code: "locale_case_ambiguity",
        detail:
          `host '${host}' collapses to the pure-ASCII domain '${collapsed}' under a ` +
          `Turkish/Azeri lowercase, but resolves to '${resolved}' under UTS-46 — a component ` +
          "that case-normalizes with an ambient locale reads a different domain than the " +
          "one the request reaches",
      },
    ];
  },
};
