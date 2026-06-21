import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DETECTORS } from "../src/detectors/registry.js";
import { STRUCTURAL_SCANS } from "../src/detectors/structural.js";
import { REASON_CODES, type ReasonCode } from "../src/schema/reason-codes.js";

// Light validation (NOT generation) that catches the common drift between code
// and docs. Paths are resolved relative to THIS test module (not process.cwd())
// so the test runs the same regardless of the working directory.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const reasonCodesDoc = readFileSync(join(REPO_ROOT, "docs", "reason-codes.md"), "utf8");
const readme = readFileSync(join(REPO_ROOT, "README.md"), "utf8");

// Each code is documented with an h3 header of the form: ### `code_name` — …
// Parse the backtick-wrapped code name out of every such header.
const DOC_CODE_RE = /^### `([a-z_]+)`/gm;
function documentedCodes(markdown: string): string[] {
  return [...markdown.matchAll(DOC_CODE_RE)].map((m) => m[1] as string);
}

describe("docs/reason-codes.md stays in sync with the REASON_CODES registry", () => {
  const registryCodes = Object.keys(REASON_CODES) as ReasonCode[];
  const docCodes = documentedCodes(reasonCodesDoc);
  const docCodeSet = new Set(docCodes);
  const registryCodeSet = new Set<string>(registryCodes);

  // 1. COMPLETENESS — every registry code is documented.
  it.each(registryCodes)("registry code %s is documented", (code) => {
    expect(docCodeSet.has(code)).toBe(true);
  });

  // 2. NO ORPHANS — every documented code is a real registry key (catches
  //    stale/renamed doc entries).
  it.each(docCodes)("documented code %s is a real REASON_CODES key", (code) => {
    expect(registryCodeSet.has(code)).toBe(true);
  });

  // 3. POLICY COVERAGE — every policy-layer code is documented under the policy
  //    section heading (i.e. its header appears after the section heading).
  it("every policy-layer code is documented under the policy section", () => {
    const policyHeadingIndex = reasonCodesDoc.search(/^## Policy codes\b/m);
    expect(policyHeadingIndex).toBeGreaterThan(-1);
    const policySection = reasonCodesDoc.slice(policyHeadingIndex);
    const policyDocCodes = new Set(documentedCodes(policySection));

    const policyCodes = registryCodes.filter((code) => REASON_CODES[code].layer === "policy");
    expect(policyCodes.length).toBeGreaterThan(0);
    for (const code of policyCodes) {
      expect(policyDocCodes.has(code)).toBe(true);
    }
  });

  // SKIP: "every detector-emitted code is registered" — emitted codes are
  // type-constrained to the ReasonCode union, so tsc enforces it at compile time.
});

describe("README detector count matches the computed total", () => {
  // 4. DETECTOR COUNT — the true count is the lexical detector registry plus the
  //    structural scans. README hardcodes this number; assert both agree.
  it("DETECTORS + STRUCTURAL_SCANS equals 34 and README states it", () => {
    const total = DETECTORS.length + STRUCTURAL_SCANS.length;
    expect(total).toBe(34);
    expect(readme.includes(String(total))).toBe(true);
  });
});
