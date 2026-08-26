import type { Detector, DetectorFinding } from "./types.js";
import { hasMalformedPunycode } from "../unicode/idna.js";
import tr46 from "tr46";

/**
 * `idna_protocol_violation` (scoring, weight 0.35 -> medium). A host label that
 * UTS-46 processing accepts but **RFC 5892 (IDNA2008) does not permit**: a
 * DISALLOWED code point, a CONTEXTJ/CONTEXTO rule violation, or a stack of
 * combining marks past any orthographic use.
 *
 * ── Why this is a separate code from `punycode_malformed` ───────────────────
 * `punycode_malformed` covers strictly LESS. It fires when an `xn--` label
 * fails to DECODE — broken base-36, a bad round-trip, a UTS-46 U-label validity
 * rule. This code fires on the opposite shape: the ACE is **well formed**, it
 * decodes cleanly, tr46 round-trips it without complaint, and the U-label it
 * yields is still not registrable under IDNA2008.
 *
 * That is the form that actually travels. A raw Unicode `.` middle dot or a
 * bare heart never survives `parse()`'s host-character rule, and a raw ZWNJ is
 * already `invisible_char` at weight 1 — but their ACE spellings sail through
 * every existing check:
 *
 *   https://xn--g6h.example.com/          -> U+2665, DISALLOWED   (was 0.00)
 *   https://xn--abcd-176a.example.com/    -> ZWNJ, CONTEXTJ       (was 0.00)
 *   https://xn--ab-0ea.example.com/       -> U+00B7, CONTEXTO     (was 0.00)
 *   https://xn--1ca20iaaaa.example.com/   -> 6 stacked marks      (was 0.00)
 *
 * ── Why it is a finding at all ──────────────────────────────────────────────
 * A protocol violation is a deterministic, offline, no-judgment observation:
 * either RFC 5892 permits the code point in that position or it does not. No
 * registry operating under IDNA2008 issues such a label, so a well-formed ACE
 * encoding of one was produced by an encoder run deliberately. Nobody types
 * `xn--g6h` by accident.
 *
 * ── Weight: 0.35, argued from the table ─────────────────────────────────────
 * Above `punycode_malformed` (0.20): a malformed ACE label is routinely a
 * truncation or copy-paste accident, whereas a *valid* ACE label encoding a
 * DISALLOWED code point took a working encoder and an intent to emit it.
 * Below `separator_lookalike` (0.50), `control_char` (0.60) and
 * `low_byte_truncation` (0.60): those are active smuggling primitives that
 * misdirect a parser about where the host ends. This one names a structural
 * anomaly without, on its own, naming a victim or hiding a boundary.
 * 0.35 is `encoding_obfuscation`'s weight, its closest peer in kind — a
 * deliberate obfuscation step that is not by itself an impersonation. It lands
 * `medium`: reviewable, stacking cleanly with `mixed_script` / `brand_*` when
 * the label is ALSO an impersonation, and not tripping the default
 * `--fail-on high` gate alone. A blocker weight (1.0) is not earned: a middle
 * dot in a non-Catalan label is a real violation that some registries have
 * historically leaked, and it does not by itself prove an attack.
 *
 * ── Precision: the version-drift direction is deliberate ────────────────────
 * The DISALLOWED test is a POSITIVE membership test on Symbol / Punctuation /
 * Separator rather than the complement of RFC 5892's LetterDigits set. Written
 * as a complement ("not a letter, mark or digit"), a code point assigned in a
 * NEWER Unicode release than the running runtime's ICU would read as
 * unassigned and therefore DISALLOWED — a false positive on the older Node in
 * the support matrix, which is the CJK-Extension-J shape `docs/architecture.md`
 * already records. Written as a positive test, the same drift produces a false
 * NEGATIVE (the check stays quiet) because a newly assigned ideograph is `Lo`
 * in every release and never `S`/`P`/`Z`. Silence under drift is the safe
 * direction and the one SC-2 asks for.
 *
 * Scoped to NON-ASCII code points. ASCII host characters are governed by the
 * parser's LDH rule and by `control_char` / `ambiguous_authority`; including
 * them here would claim territory this code does not own (and would flag the
 * LDH hyphen, which is `Pd`).
 *
 * CONTEXTJ is delegated to `tr46`'s `checkJoiners`, which implements RFC 5892
 * A.1/A.2 including the Joining_Type regex — satisfying FR-LIB-1 (do not
 * hand-roll IDNA) rather than reimplementing the rule here.
 *
 * Pure, synchronous, no network/fs.
 */

const ZWNJ = "‌";
const ZWJ = "‍";

/** RFC 5892 A.3-A.7 — the five code points whose validity is contextual. */
const MIDDLE_DOT = "·";
const GREEK_KERAIA = "͵";
const HEBREW_GERESH = "׳";
const HEBREW_GERSHAYIM = "״";
const KATAKANA_MIDDLE_DOT = "・";

const CONTEXTO_CHARS = new Set([
  MIDDLE_DOT,
  GREEK_KERAIA,
  HEBREW_GERESH,
  HEBREW_GERSHAYIM,
  KATAKANA_MIDDLE_DOT,
]);

/**
 * RFC 5892 §2.6 (F.1) PVALID exceptions that fall in a Symbol/Punctuation
 * category and would otherwise be caught by the DISALLOWED test below. The
 * other PVALID exceptions (U+00DF, U+03C2, U+3007) are already `Ll`/`Nl` and
 * need no entry.
 */
const PVALID_EXCEPTIONS = new Set(["۽", "۾", "་"]);

/**
 * RFC 5892 §2.6 (F.4) DISALLOWED exceptions that are NOT Symbol/Punctuation —
 * modifier letters and combining marks the general-category test cannot see, so
 * they are listed explicitly. U+0640 ARABIC TATWEEL and U+3031..U+3035 are `Lm`;
 * U+302E/U+302F are combining marks.
 */
const DISALLOWED_EXCEPTIONS = new Set([
  "ـ",
  "ߺ",
  "〮",
  "〯",
  "〱",
  "〲",
  "〳",
  "〴",
  "〵",
  "〻",
]);

/** Symbol, Punctuation or Separator — the DISALLOWED classes this code claims. */
const SYMBOL_PUNCT_SEP = /[\p{S}\p{P}\p{Z}]/u;
const COMBINING_MARK = /\p{M}/u;
const ARABIC_INDIC_DIGIT = /[٠-٩]/u;
const EXT_ARABIC_INDIC_DIGIT = /[۰-۹]/u;

/**
 * Longest run of combining marks a legitimate orthography needs. Vietnamese
 * stacks two, Devanagari and Thai reach three or four in edge cases; five is
 * past every writing system and is the stacking-diacritic ("Zalgo") shape.
 */
const MAX_COMBINING_RUN = 4;

/** True when every code point in `s` is ASCII. */
function isAscii(s: string): boolean {
  return /^[\x00-\x7f]*$/.test(s);
}

/**
 * RFC 5892 A.1/A.2, via tr46. Returns true when the label carries a ZWNJ or ZWJ
 * that `checkJoiners` rejects — i.e. a ZWJ not preceded by a Virama, or a ZWNJ
 * that is neither Virama-preceded nor inside the permitted Joining_Type run.
 */
function violatesContextJ(label: string): boolean {
  if (!label.includes(ZWNJ) && !label.includes(ZWJ)) return false;
  try {
    return (
      tr46.toASCII(label, { transitionalProcessing: false, checkJoiners: true }) === null
    );
  } catch {
    // Never turn an unexpected library throw into a finding (SC-2).
    return false;
  }
}

/** The CONTEXTO rule violated at `i`, or null when the code point is in context. */
function contextOViolation(label: string, chars: string[], i: number): string | null {
  const ch = chars[i]!;
  const prev = i > 0 ? chars[i - 1]! : null;
  const next = i + 1 < chars.length ? chars[i + 1]! : null;

  switch (ch) {
    // A.3 — MIDDLE DOT is valid only between two `l` (Catalan `l·l`).
    case MIDDLE_DOT:
      return prev === "l" && next === "l"
        ? null
        : "U+00B7 MIDDLE DOT outside the Catalan 'l·l' context (RFC 5892 A.3)";
    // A.4 — GREEK KERAIA must be followed by a Greek character.
    case GREEK_KERAIA:
      return next !== null && /\p{Script=Greek}/u.test(next)
        ? null
        : "U+0375 GREEK LOWER NUMERAL SIGN not followed by a Greek character (RFC 5892 A.4)";
    // A.5 / A.6 — GERESH and GERSHAYIM must be preceded by a Hebrew character.
    case HEBREW_GERESH:
      return prev !== null && /\p{Script=Hebrew}/u.test(prev)
        ? null
        : "U+05F3 HEBREW PUNCTUATION GERESH not preceded by a Hebrew character (RFC 5892 A.5)";
    case HEBREW_GERSHAYIM:
      return prev !== null && /\p{Script=Hebrew}/u.test(prev)
        ? null
        : "U+05F4 HEBREW PUNCTUATION GERSHAYIM not preceded by a Hebrew character (RFC 5892 A.6)";
    // A.7 — KATAKANA MIDDLE DOT needs Hiragana, Katakana or Han in the label.
    case KATAKANA_MIDDLE_DOT:
      return /[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]/u.test(label)
        ? null
        : "U+30FB KATAKANA MIDDLE DOT in a label with no Hiragana, Katakana or Han character (RFC 5892 A.7)";
    default:
      return null;
  }
}

/** The first RFC 5892 violation in `label`, or null when the label is clean. */
function labelViolation(label: string): string | null {
  if (label === "" || isAscii(label)) return null;

  if (violatesContextJ(label)) {
    const joiner = label.includes(ZWNJ) ? "U+200C ZWNJ" : "U+200D ZWJ";
    return `${joiner} outside its permitted joining context (RFC 5892 A.1/A.2 CONTEXTJ)`;
  }

  const chars = [...label];

  // RFC 5892 A.8/A.9 — the two Arabic digit blocks may not share a label.
  if (ARABIC_INDIC_DIGIT.test(label) && EXT_ARABIC_INDIC_DIGIT.test(label)) {
    return "mixes U+0660..U+0669 with U+06F0..U+06F9 Arabic-Indic digits (RFC 5892 A.8/A.9)";
  }

  for (let i = 0; i < chars.length; i += 1) {
    const ch = chars[i]!;
    if (isAscii(ch)) continue;

    if (CONTEXTO_CHARS.has(ch)) {
      const violation = contextOViolation(label, chars, i);
      if (violation !== null) return violation;
      continue;
    }

    if (DISALLOWED_EXCEPTIONS.has(ch)) {
      return `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")} is DISALLOWED by RFC 5892 (exception table F.4)`;
    }

    if (PVALID_EXCEPTIONS.has(ch)) continue;

    if (SYMBOL_PUNCT_SEP.test(ch)) {
      return `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")} is a symbol/punctuation code point, DISALLOWED in an IDNA2008 label (RFC 5892 §2.1)`;
    }
  }

  // Stacked combining marks: a run longer than any orthography needs.
  let run = 0;
  for (const ch of chars) {
    if (COMBINING_MARK.test(ch)) {
      run += 1;
      if (run > MAX_COMBINING_RUN) {
        return `${run} combining marks stacked on one base character (limit ${MAX_COMBINING_RUN})`;
      }
    } else {
      run = 0;
    }
  }

  return null;
}

export const idnaProtocolViolation: Detector = {
  id: "idna_protocol_violation",
  layer: "lexical",
  run(ctx): DetectorFinding[] {
    if (ctx.host === "" || ctx.isIp) return [];
    // A label that does not even DECODE belongs to `punycode_malformed`; the
    // two never double-flag.
    if (hasMalformedPunycode(ctx.host)) return [];

    const labels = ctx.hostUnicode.replace(/\.$/, "").split(".");
    for (const label of labels) {
      const violation = labelViolation(label);
      if (violation !== null) {
        return [
          {
            code: "idna_protocol_violation",
            detail:
              `host label '${label}' is not permitted under IDNA2008: ${violation} — ` +
              "the label decodes cleanly but no IDNA2008 registry issues it",
          },
        ];
      }
    }
    return [];
  },
};
