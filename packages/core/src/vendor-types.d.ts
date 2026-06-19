/** Minimal type declaration for the pure-JS `tr46` UTS-46 implementation. */
declare module "tr46" {
  interface Tr46Options {
    checkHyphens?: boolean;
    checkBidi?: boolean;
    checkJoiners?: boolean;
    useSTD3ASCIIRules?: boolean;
    transitionalProcessing?: boolean;
    verifyDNSLength?: boolean;
  }
  /** Returns the ASCII (ACE / punycode) form, or `null` on failure. */
  export function toASCII(domainName: string, options?: Tr46Options): string | null;
  /** Returns the Unicode (U-label) form plus a processing-error flag. */
  export function toUnicode(
    domainName: string,
    options?: Tr46Options,
  ): { domain: string; error: boolean };
}
