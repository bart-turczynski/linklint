import type { Detector } from "./types.js";
import { normalizationDelta } from "./normalization-delta.js";
import { confusableChar } from "./confusable-char.js";
import { mixedScript } from "./mixed-script.js";
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
import { punycodeMalformed } from "./punycode-malformed.js";

/**
 * Ordered list of lexical detectors run by the default `inspect()` path,
 * in FR-D-1..12 order. Reasons are re-ordered by weight at serialization time;
 * this order only affects execution and `checksSkipped` ordering.
 */
export const DETECTORS: Detector[] = [
  normalizationDelta, // FR-D-1  (info)
  confusableChar, // FR-D-2  (info)
  mixedScript, // FR-D-3  (scoring)
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
  punycodeMalformed, // E5      (scoring, low)
];

export {
  normalizationDelta,
  confusableChar,
  mixedScript,
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
  punycodeMalformed,
};
