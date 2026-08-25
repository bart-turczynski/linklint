import type { Detector } from "./types.js";
import { isFileExtensionTld } from "../data/file-extension-tlds.js";

/**
 * `file_extension_tld`. SCORING. Owns the extension-confusable TLDs `.zip` /
 * `.mov` exclusively. It is the only TLD-shaped scoring signal that survives:
 * the curated high-abuse `risky_tld` bucket was deleted in schema `1.10`
 * (`LINK-brsntven`) because list membership is a fact about the world, while a
 * `.zip` host that reads as a filename is a false claim the STRING makes about
 * its own type (architecture §1.1 form 3).
 *
 * A registrable domain on a file-extension TLD can masquerade as a downloadable
 * file: `invoice.zip` reads as an archive, `setup.mov` as a video. Fires only on
 * the masquerade STRUCTURE, never on TLD membership alone:
 *  - **bare filename** — the host is exactly `stem.zip` with no subdomain, so it
 *    reads as a filename rather than a website (`https://invoice.zip/`);
 *  - **hidden behind userinfo** — a `…@stem.zip` authority, the lure in
 *    `github.com∕x@update.zip` (a slash-look-alike pushes the brand into
 *    userinfo and the real host is the file-looking `.zip`).
 *
 * A deep-subdomain `.zip` host with no userinfo (`cdn.assets.acme.zip`) reads as
 * an ordinary site, so it is left alone (SC-2). Weight 0.4 (medium), and combines
 * with the structural detectors and `userinfo_present`.
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
