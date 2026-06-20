import type { Detector } from "./types.js";
import { normalizationDelta } from "./normalization-delta.js";
import { confusableChar } from "./confusable-char.js";
import { mixedScript } from "./mixed-script.js";
import { asciiHomoglyph } from "./ascii-homoglyph.js";
import { invisibleChar } from "./invisible-char.js";
import { bidiOverride } from "./bidi-override.js";
import { userinfoPresent } from "./userinfo-present.js";
import { ipObfuscation } from "./ip-obfuscation.js";
import { embeddedDomain } from "./embedded-domain.js";
import { riskyTld } from "./risky-tld.js";
import { fileExtensionTld } from "./file-extension-tld.js";
import { encodingObfuscation } from "./encoding-obfuscation.js";
import { dangerousScheme } from "./dangerous-scheme.js";
import { confusableInPath } from "./confusable-in-path.js";
import { brandInPath } from "./brand-in-path.js";
import { brandLookalike } from "./brand-lookalike.js";
import { skeletonCollision } from "./skeleton-collision.js";
import { combosquatting } from "./combosquatting.js";
import { soundsquatting } from "./soundsquatting.js";
import { bitsquatting } from "./bitsquatting.js";
import { baitTokens } from "./bait-tokens.js";
import { openRedirectParam } from "./open-redirect-param.js";
import { suspiciousExtension } from "./suspicious-extension.js";
import { punycodeMalformed } from "./punycode-malformed.js";
import { excessiveSubdomainDepth } from "./excessive-subdomain-depth.js";

/**
 * Ordered list of lexical detectors run by the default `inspect()` path,
 * in FR-D-1..12 order. Reasons are re-ordered by weight at serialization time;
 * this order only affects execution and `checksSkipped` ordering.
 */
export const DETECTORS: Detector[] = [
  normalizationDelta, // FR-D-1  (info)
  confusableChar, // FR-D-2  (info)
  mixedScript, // FR-D-3  (scoring)
  asciiHomoglyph, // J4      (scoring, low)
  invisibleChar, // FR-D-4  (scoring)
  bidiOverride, // FR-D-5  (scoring)
  userinfoPresent, // FR-D-6  (scoring)
  ipObfuscation, // FR-D-7  (scoring)
  embeddedDomain, // FR-D-8  (scoring)
  riskyTld, // FR-D-9  (scoring, low)
  fileExtensionTld, // J6      (scoring)
  encodingObfuscation, // FR-D-10 (scoring)
  dangerousScheme, // FR-D-11 (scoring)
  confusableInPath, // FR-D-12 (info)
  brandInPath, // J7      (scoring, low)
  brandLookalike, // G2      (scoring)
  skeletonCollision, // E3   (scoring) — non-ASCII whole-label homograph
  combosquatting, // G3      (scoring)
  soundsquatting, // T2      (scoring) — phonetic homophone of a brand
  bitsquatting, // T3      (scoring, low) — single-bit-flip neighbor of a brand
  baitTokens, // G4      (scoring, low)
  openRedirectParam, // I2      (scoring)
  suspiciousExtension, // I1      (scoring)
  punycodeMalformed, // E5      (scoring, low)
  excessiveSubdomainDepth, // I3 (scoring, low)
];

export {
  normalizationDelta,
  confusableChar,
  mixedScript,
  asciiHomoglyph,
  invisibleChar,
  bidiOverride,
  userinfoPresent,
  ipObfuscation,
  embeddedDomain,
  riskyTld,
  fileExtensionTld,
  encodingObfuscation,
  dangerousScheme,
  confusableInPath,
  brandInPath,
  brandLookalike,
  skeletonCollision,
  combosquatting,
  soundsquatting,
  bitsquatting,
  baitTokens,
  openRedirectParam,
  suspiciousExtension,
  punycodeMalformed,
  excessiveSubdomainDepth,
};
