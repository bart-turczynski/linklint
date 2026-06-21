import type { CheckDescriptor } from "./descriptor.js";

// Structural scans (run ahead of parse, in STRUCTURAL_SCANS order).
import { scanAmbiguousAuthority } from "./ambiguous-authority.js";
import { scanSeparatorLookalike } from "./separator-lookalike.js";
import { scanIdnaMappingAmbiguity } from "./idna-mapping-ambiguity.js";
import { scanControlChar } from "./control-char.js";

// Parsed detectors (in DETECTORS order).
import { normalizationDelta } from "./normalization-delta.js";
import { confusableChar } from "./confusable-char.js";
import { mixedScript } from "./mixed-script.js";
import { asciiHomoglyph } from "./ascii-homoglyph.js";
import { invisibleChar } from "./invisible-char.js";
import { bidiOverride } from "./bidi-override.js";
import { userinfoPresent } from "./userinfo-present.js";
import { ipObfuscation } from "./ip-obfuscation.js";
import { ipClassification } from "./ip-classification.js";
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
 * THE single descriptor source for all 30 checks. `STRUCTURAL_SCANS`
 * (structural.ts) and `DETECTORS` (registry.ts) are both DERIVED from this
 * array — add a check here once and both runtime arrays pick it up.
 *
 * Order matches today's runtime order exactly: the 4 structural scans first
 * (STRUCTURAL_SCANS order), then the 26 parsed detectors (DETECTORS order).
 * Each descriptor reuses the existing detector object / scan thunk's `run`;
 * detector logic is unchanged. `skipReportable: true` for every check (a
 * runtime failure is recorded as `lexical:<id>` in `checksSkipped`).
 *
 * Weights and summaries remain owned by `schema/reason-codes.ts`. This registry
 * owns only check identity, layer, the emitted reason codes, and the run wiring.
 */
export const CHECKS: CheckDescriptor[] = [
  // --- Structural scans (lexical layer) ---
  {
    id: "ambiguous_authority",
    layer: "lexical",
    phase: "structural",
    emits: ["ambiguous_authority"],
    skipReportable: true,
    run: (ctx) => scanAmbiguousAuthority(ctx.prepared, ctx.authority),
  },
  {
    id: "separator_lookalike",
    layer: "lexical",
    phase: "structural",
    emits: ["separator_lookalike"],
    skipReportable: true,
    run: (ctx) => scanSeparatorLookalike(ctx.prepared, ctx.authority),
  },
  {
    id: "idna_mapping_ambiguity",
    layer: "lexical",
    phase: "structural",
    emits: ["idna_mapping_ambiguity"],
    skipReportable: true,
    run: (ctx) => scanIdnaMappingAmbiguity(ctx.prepared, ctx.authority),
  },
  {
    id: "control_char",
    layer: "lexical",
    phase: "structural",
    emits: ["control_char"],
    skipReportable: true,
    run: (ctx) => scanControlChar(ctx.prepared, ctx.runtime, ctx.authority),
  },

  // --- Parsed detectors (FR-D order) ---
  {
    id: normalizationDelta.id,
    layer: normalizationDelta.layer,
    phase: "parsed",
    emits: ["normalization_delta"],
    skipReportable: true,
    run: normalizationDelta.run,
  },
  {
    id: confusableChar.id,
    layer: confusableChar.layer,
    phase: "parsed",
    emits: ["confusable_char"],
    skipReportable: true,
    run: confusableChar.run,
  },
  {
    id: mixedScript.id,
    layer: mixedScript.layer,
    phase: "parsed",
    emits: ["mixed_script"],
    skipReportable: true,
    run: mixedScript.run,
  },
  {
    id: asciiHomoglyph.id,
    layer: asciiHomoglyph.layer,
    phase: "parsed",
    emits: ["ascii_homoglyph"],
    skipReportable: true,
    run: asciiHomoglyph.run,
  },
  {
    id: invisibleChar.id,
    layer: invisibleChar.layer,
    phase: "parsed",
    emits: ["invisible_char"],
    skipReportable: true,
    run: invisibleChar.run,
  },
  {
    id: bidiOverride.id,
    layer: bidiOverride.layer,
    phase: "parsed",
    emits: ["bidi_override"],
    skipReportable: true,
    run: bidiOverride.run,
  },
  {
    id: userinfoPresent.id,
    layer: userinfoPresent.layer,
    phase: "parsed",
    emits: ["userinfo_present"],
    skipReportable: true,
    run: userinfoPresent.run,
  },
  {
    id: ipObfuscation.id,
    layer: ipObfuscation.layer,
    phase: "parsed",
    emits: ["ip_obfuscation"],
    skipReportable: true,
    run: ipObfuscation.run,
  },
  {
    id: ipClassification.id,
    layer: ipClassification.layer,
    phase: "parsed",
    emits: [
      "ip_cloud_metadata",
      "ip_loopback",
      "ip_link_local",
      "ip_private",
      "ip_reserved",
    ],
    skipReportable: true,
    run: ipClassification.run,
  },
  {
    id: embeddedDomain.id,
    layer: embeddedDomain.layer,
    phase: "parsed",
    emits: ["embedded_domain_in_subdomain"],
    skipReportable: true,
    run: embeddedDomain.run,
  },
  {
    id: riskyTld.id,
    layer: riskyTld.layer,
    phase: "parsed",
    emits: ["risky_tld"],
    skipReportable: true,
    run: riskyTld.run,
  },
  {
    id: fileExtensionTld.id,
    layer: fileExtensionTld.layer,
    phase: "parsed",
    emits: ["file_extension_tld"],
    skipReportable: true,
    run: fileExtensionTld.run,
  },
  {
    id: encodingObfuscation.id,
    layer: encodingObfuscation.layer,
    phase: "parsed",
    emits: ["encoding_obfuscation"],
    skipReportable: true,
    run: encodingObfuscation.run,
  },
  {
    id: dangerousScheme.id,
    layer: dangerousScheme.layer,
    phase: "parsed",
    emits: ["dangerous_scheme"],
    skipReportable: true,
    run: dangerousScheme.run,
  },
  {
    id: confusableInPath.id,
    layer: confusableInPath.layer,
    phase: "parsed",
    emits: ["confusable_in_path"],
    skipReportable: true,
    run: confusableInPath.run,
  },
  {
    id: brandInPath.id,
    layer: brandInPath.layer,
    phase: "parsed",
    emits: ["brand_in_path"],
    skipReportable: true,
    run: brandInPath.run,
  },
  {
    id: brandLookalike.id,
    layer: brandLookalike.layer,
    phase: "parsed",
    emits: ["brand_homoglyph", "brand_lookalike"],
    skipReportable: true,
    run: brandLookalike.run,
  },
  {
    id: skeletonCollision.id,
    layer: skeletonCollision.layer,
    phase: "parsed",
    emits: ["homograph_skeleton_collision"],
    skipReportable: true,
    run: skeletonCollision.run,
  },
  {
    id: combosquatting.id,
    layer: combosquatting.layer,
    phase: "parsed",
    emits: ["brand_combosquat"],
    skipReportable: true,
    run: combosquatting.run,
  },
  {
    id: soundsquatting.id,
    layer: soundsquatting.layer,
    phase: "parsed",
    emits: ["brand_soundsquat"],
    skipReportable: true,
    run: soundsquatting.run,
  },
  {
    id: bitsquatting.id,
    layer: bitsquatting.layer,
    phase: "parsed",
    emits: ["brand_bitsquat"],
    skipReportable: true,
    run: bitsquatting.run,
  },
  {
    id: baitTokens.id,
    layer: baitTokens.layer,
    phase: "parsed",
    emits: ["bait_tokens"],
    skipReportable: true,
    run: baitTokens.run,
  },
  {
    id: openRedirectParam.id,
    layer: openRedirectParam.layer,
    phase: "parsed",
    emits: ["open_redirect_param"],
    skipReportable: true,
    run: openRedirectParam.run,
  },
  {
    id: suspiciousExtension.id,
    layer: suspiciousExtension.layer,
    phase: "parsed",
    emits: ["suspicious_extension"],
    skipReportable: true,
    run: suspiciousExtension.run,
  },
  {
    id: punycodeMalformed.id,
    layer: punycodeMalformed.layer,
    phase: "parsed",
    emits: ["punycode_malformed"],
    skipReportable: true,
    run: punycodeMalformed.run,
  },
  {
    id: excessiveSubdomainDepth.id,
    layer: excessiveSubdomainDepth.layer,
    phase: "parsed",
    emits: ["excessive_subdomain_depth"],
    skipReportable: true,
    run: excessiveSubdomainDepth.run,
  },
];
