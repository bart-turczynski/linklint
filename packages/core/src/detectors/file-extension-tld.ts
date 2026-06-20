import type { Detector } from "./types.js";
import { isFileExtensionTld } from "../data/risky-tlds.js";

/**
 * J6 — `file_extension_tld` (Epic J). SCORING. Sharper successor to `risky_tld`
 * for the extension-confusable TLDs `.zip` / `.mov`, which it owns exclusively
 * (those TLDs were removed from the `risky_tld` set so the two never double-count).
 *
 * A registrable domain on a file-extension TLD can masquerade as a downloadable
 * file: `invoice.zip` reads as an archive, `setup.mov` as a video. Fires only on
 * the masquerade STRUCTURE so it stays sharper than the generic risky-TLD bucket:
 *  - **bare filename** — the host is exactly `stem.zip` with no subdomain, so it
 *    reads as a filename rather than a website (`https://invoice.zip/`);
 *  - **hidden behind userinfo** — a `…@stem.zip` authority, the lure in
 *    `github.com∕x@update.zip` (a J2 slash-look-alike pushes the brand into
 *    userinfo and the real host is the file-looking `.zip`).
 *
 * A deep-subdomain `.zip` host with no userinfo (`cdn.assets.acme.zip`) reads as
 * an ordinary site, so it is left alone (SC-2). Weight 0.4 (medium) — higher than
 * `risky_tld` (0.15) and combines with J1/J2/`userinfo_present`.
 */
export const fileExtensionTld: Detector = {
  id: "file_extension_tld",
  layer: "lexical",
  run(ctx) {
    if (!ctx.publicSuffix || !ctx.registrableDomain) return [];
    const tld = ctx.publicSuffixTld!;
    if (!isFileExtensionTld(tld)) return [];

    const bareFilename = !ctx.subdomain; // host is exactly `stem.<ext>`
    const hiddenByUserinfo = ctx.userinfo !== null && ctx.userinfo !== "";
    if (!bareFilename && !hiddenByUserinfo) return [];

    const how = bareFilename
      ? `the host is exactly '${ctx.registrableDomain}', which reads as a filename`
      : `'${ctx.registrableDomain}' is hidden behind userinfo, so it reads as a file/path token`;
    return [
      {
        code: "file_extension_tld",
        detail:
          `registrable domain '${ctx.registrableDomain}' uses the file-extension TLD '.${tld}' — ` +
          `${how}, not a website`,
      },
    ];
  },
};
