import type { Detector } from "./types.js";
import type { ParsedCheckDescriptor } from "./descriptor.js";
import { CHECKS } from "./checks.js";
import { normalizationDelta } from "./normalization-delta.js";
import { confusableChar } from "./confusable-char.js";
import { mixedScript } from "./mixed-script.js";
import { asciiHomoglyph } from "./ascii-homoglyph.js";
import { invisibleChar } from "./invisible-char.js";
import { bidiOverride } from "./bidi-override.js";
import { userinfoPresent } from "./userinfo-present.js";
import { ipObfuscation } from "./ip-obfuscation.js";
import { ipClassification } from "./ip-classification.js";
import { ambiguousNumericHost } from "./ambiguous-numeric-host.js";
import { embeddedDomain } from "./embedded-domain.js";
import { fileExtensionTld } from "./file-extension-tld.js";
import { encodingObfuscation } from "./encoding-obfuscation.js";
import { dangerousScheme } from "./dangerous-scheme.js";
import { confusableInPath } from "./confusable-in-path.js";
import { brandHomoglyph } from "./brand-homoglyph.js";
import { skeletonCollision } from "./skeleton-collision.js";
import { latinSkeletonHomograph } from "./latin-skeleton-homograph.js";
import { localeCaseCollapse } from "./locale-case-collapse.js";
import { idnHost } from "./idn-host.js";
import { openRedirectParam } from "./open-redirect-param.js";
import { suspiciousExtension } from "./suspicious-extension.js";
import { punycodeMalformed } from "./punycode-malformed.js";
import { idnaProtocolViolation } from "./idna-protocol-violation.js";
import { percentEncodingMalformed } from "./percent-encoding-malformed.js";
import { lowByteTruncation } from "./low-byte-truncation.js";
import { headerShapedToken } from "./header-shaped-token.js";
import { fqdnRootLabel } from "./fqdn-root-label.js";
import { hostLengthUnresolvable } from "./host-length-unresolvable.js";
import { specialUseName } from "./special-use-name.js";
import { excessiveSubdomainDepth } from "./excessive-subdomain-depth.js";
import { promptInjection } from "./prompt-injection.js";
import { credentialHarvesting } from "./credential-harvesting.js";
import { dataExfiltration } from "./data-exfiltration.js";
import { ssrfCloudMetadata } from "./ssrf-cloud-metadata.js";

/**
 * Ordered list of lexical detectors run by the default `inspect()` path, in
 * FR-D-1..12 order. DERIVED from the unified {@link CHECKS} registry: the
 * parsed-phase descriptors, in registry order, projected onto the `{id, layer,
 * run}` Detector shape. Reasons are re-ordered by weight at serialization time;
 * this order only affects execution and `checksSkipped` ordering.
 */
export const DETECTORS: Detector[] = CHECKS.filter(
  (c): c is ParsedCheckDescriptor => c.phase === "parsed",
).map((c) => ({
  id: c.id,
  layer: c.layer,
  run: c.run,
  ...(c.agentGated ? { agentGated: true } : {}),
}));

export {
  normalizationDelta,
  confusableChar,
  mixedScript,
  asciiHomoglyph,
  invisibleChar,
  bidiOverride,
  userinfoPresent,
  ipObfuscation,
  ipClassification,
  ambiguousNumericHost,
  embeddedDomain,
  fileExtensionTld,
  encodingObfuscation,
  dangerousScheme,
  confusableInPath,
  brandHomoglyph,
  skeletonCollision,
  latinSkeletonHomograph,
  localeCaseCollapse,
  idnHost,
  openRedirectParam,
  suspiciousExtension,
  punycodeMalformed,
  idnaProtocolViolation,
  percentEncodingMalformed,
  lowByteTruncation,
  headerShapedToken,
  hostLengthUnresolvable,
  specialUseName,
  fqdnRootLabel,
  excessiveSubdomainDepth,
  promptInjection,
  credentialHarvesting,
  dataExfiltration,
  ssrfCloudMetadata,
};
