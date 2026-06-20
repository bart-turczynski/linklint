import type { Detector } from "./types.js";

/**
 * `suspicious_extension`. SCORING. A lexical, brand-free signal for
 * direct-download malware links: the URL **path** ends in a dangerous executable
 * file extension, or in a deceptive double-extension that lures a click.
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
 * Precision (SC-2): only the last segment is considered, so a `.exe` mid-path
 * never matches; a trailing-dot or extensionless segment never fires; an empty
 * path or bare `/` returns []. Weight 0.5 (medium) — a direct executable link is
 * a strong standalone signal that compounds with the authority/encoding tricks.
 */
export const suspiciousExtension: Detector = {
  id: "suspicious_extension",
  layer: "lexical",
  run(ctx) {
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
