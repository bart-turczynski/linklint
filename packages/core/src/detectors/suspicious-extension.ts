import { isOpaqueScheme } from "../parse/syntax.js";
import type { Detector } from "./types.js";

/**
 * `suspicious_extension`. SCORING. A lexical, brand-free signal for
 * direct-download malware links: the URL **path** ends in a dangerous executable
 * file extension, or in a deceptive double-extension that lures a click.
 *
 * **Scheme gate (LINK-avefryhe): hierarchical schemes only.** The detector runs
 * when the input has a *hierarchical* path — any scheme that is not one of the
 * parser's `OPAQUE_SCHEMES` (`mailto`, `tel`, `about`, `javascript`, `data`,
 * `vbscript`, `blob`), plus scheme-less input, which is always host-based. The
 * rule reuses the notion `parse/syntax.ts` already owns rather than inventing a
 * second list, and it is deliberately NOT "http/https only": `ftp://host/x.exe`
 * and `file:///tmp/setup.exe` are exactly the direct-download shape this
 * detector exists for.
 *
 * An opaque scheme has no authority and no path — its whole body is a single
 * opaque string that `parseRawParts()` projects onto `ctx.path` because that is
 * the only field available. Reading a filename and an extension off it is a
 * category error: for `mailto:a@b.com` the last "segment" is `a@b.com`, which
 * splits to `['a@b','com']`, and `com` is in the dangerous set as the DOS COM
 * executable — so every `mailto:` to a `.com` address fired at 0.5/medium. That
 * is not a tuning miss but an architecture §1.1 scope violation: the string
 * makes no false claim about itself, no two readers disagree about it, and
 * `normalize(input) === input`, so none of the three settled forms of claim (a)
 * holds and it must not be a scoring finding at all.
 *
 * Nothing real is lost at the gate. `javascript:`, `data:`, `vbscript:` and
 * `blob:` already score 0.9 on `dangerous_scheme`, which is the finding on them;
 * an extension read off their body was never a download filename.
 *
 * Two structures fire (both look at the last path segment only — the filename
 * after the final `/`, ignoring query/fragment):
 *  - **double extension** — the filename has ≥2 dot-separated extension parts and
 *    the LAST is dangerous (`invoice.pdf.exe`, `report.doc.scr`). The strongest
 *    lure: the visible inner extension reads as a safe document while the real,
 *    trailing extension is an executable.
 *  - **single dangerous extension** — the filename ends in one dangerous
 *    executable extension (`setup.exe`, `screensaver.scr`).
 *
 * Dangerous set (case-insensitive): the issue's named class
 * `.exe/.scr/.apk/.iso/.bat/.msi` plus conservative additions of the same
 * executable/installer class (`cmd`, `com`, `vbs`, `jar`, `dmg`, `pkg`, `dll`,
 * `msix`, `ps1`, `deb`). A `.zip` archive is intentionally NOT in the set — an
 * archive download is ordinary and would over-flag (SC-2).
 *
 * Precision (SC-2): an opaque scheme never reaches the scan at all; only the
 * last segment is considered, so a `.exe` mid-path never matches; a trailing-dot
 * or extensionless segment never fires; an empty path or bare `/` returns [].
 * The `.com` entry stays — `http://host/setup.com` is a real direct download and
 * removing it to silence `mailto:` would have traded the false positive for a
 * false negative. Weight 0.5 (medium) — a direct executable link is
 * a strong standalone signal that compounds with the authority/encoding tricks.
 */
export const suspiciousExtension: Detector = {
  id: "suspicious_extension",
  layer: "lexical",
  run(ctx) {
    // Scheme gate: an opaque scheme's body is not a path (see docblock). A null
    // scheme is scheme-less input (`example.com/setup.exe`), which is always
    // host-based and hierarchical.
    if (ctx.scheme !== null && isOpaqueScheme(ctx.scheme.toLowerCase())) return [];

    const path = ctx.path;
    if (!path) return [];

    // Last path segment (the filename), after the final "/".
    const segment = path.slice(path.lastIndexOf("/") + 1);
    if (!segment) return [];

    // Dot-separated parts. A leading dot (".bashrc") yields an empty first part,
    // and a trailing dot ("foo.") yields an empty last part.
    const parts = segment.split(".");
    if (parts.length < 2) return []; // no extension at all

    const last = (parts[parts.length - 1] ?? "").toLowerCase();
    if (last === "" || !DANGEROUS_EXTENSIONS.has(last)) return [];

    // Double extension: ≥2 non-empty extension parts after a non-empty stem.
    // e.g. "invoice.pdf.exe" → ["invoice","pdf","exe"]; the inner "pdf" is the lure.
    const stem = parts[0] ?? "";
    const inner = parts.length >= 3 ? (parts[parts.length - 2] ?? "") : "";
    const isDouble = parts.length >= 3 && stem !== "" && inner !== "";

    const detail = isDouble
      ? `path ends in a deceptive double-extension '.${inner}.${last}' — ` +
        `the visible '.${inner}' reads as a safe file while the real extension '.${last}' is an executable`
      : `path ends in the dangerous executable extension '.${last}' — a direct-download link`;

    return [{ code: "suspicious_extension", detail }];
  },
};

/**
 * Dangerous executable / installer extensions (lowercase). Anchored on the
 * issue's named set `.exe/.scr/.apk/.iso/.bat/.msi`; the rest are conservative
 * additions of the same executable class. `.zip` and other archives are
 * deliberately excluded.
 */
const DANGEROUS_EXTENSIONS = new Set<string>([
  "exe",
  "scr",
  "apk",
  "iso",
  "bat",
  "msi",
  "cmd",
  "com",
  "vbs",
  "jar",
  "dmg",
  "pkg",
  "dll",
  "msix",
  "ps1",
  "deb",
]);
