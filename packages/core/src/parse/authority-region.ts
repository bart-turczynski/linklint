/**
 * Raw authority-region isolation, shared by the structural detectors
 * (`ambiguous_authority`, `separator_lookalike`, …). These detectors look for
 * tricks in the parts `parse()` discards, so they work on the prepared raw
 * string rather than the parsed `InspectionContext`.
 *
 * This projects from the validation-free raw tokenizer so backslashes, extra
 * slashes, and delimiter look-alikes survive to be inspected.
 */

import { tokenizeRawUrl, type RawUrlTokens } from "./raw-tokens.js";

export interface AuthorityRegion {
  scheme: string | null;
  /** True for a scheme-relative `//host` (or `\\host`) form with no scheme. */
  protocolRelative: boolean;
  /** Leading run of `/` and `\` that introduced the authority (e.g. `//`, `///`, `/\`). */
  separator: string;
  /** Authority token as written, up to the first ASCII `/` `?` or `#`. */
  authority: string;
  /** Raw path including its leading slashes (may be ""). */
  path: string;
  /** Raw fragment without the leading `#`, or null. */
  fragment: string | null;
  /** True for an opaque scheme with no authority (`javascript:alert(1)`). */
  opaque: boolean;
}

/** Split a prepared input into its raw authority region and surrounding parts. */
export function authorityRegion(
  prepared: string,
  tokens: RawUrlTokens = tokenizeRawUrl(prepared),
): AuthorityRegion {
  return {
    scheme: tokens.scheme,
    protocolRelative: tokens.protocolRelative,
    separator: tokens.authorityIntroducer,
    authority: tokens.authority,
    path: tokens.path,
    fragment: tokens.fragment,
    opaque: tokens.opaque,
  };
}
