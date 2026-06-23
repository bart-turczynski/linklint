import { describe, expect, it } from "vitest";
import { CHECKS } from "../../src/detectors/checks.js";
import { REASON_CODES } from "../../src/schema/reason-codes.js";
import { CORPUS, type CorpusSuccessCriterion } from "./corpus.js";

const REQUIRED_SUCCESS_CRITERIA: CorpusSuccessCriterion[] = ["SC-1", "SC-1a", "SC-2", "SC-2a"];

const detectorOwnedCodes = new Set<string>(
  Object.keys(REASON_CODES).filter(
    (code) => REASON_CODES[code as keyof typeof REASON_CODES].layer !== "policy" && code !== "parse_error",
  ),
);

const checkOwnedCodes = new Set<string>(CHECKS.flatMap((check) => [...check.emits]));

describe("corpus acceptance coverage", () => {
  it("tags every row with success-criteria and detector-family metadata", () => {
    for (const row of CORPUS) {
      expect(row.acceptance?.successCriteria.length, `${row.input}: missing success criteria`).toBeGreaterThan(0);
      expect(row.acceptance?.detectorFamilies, `${row.input}: missing detector families`).toBeDefined();
    }
  });

  it.each(REQUIRED_SUCCESS_CRITERIA)("has corpus rows for %s", (criterion) => {
    const matchingRows = CORPUS.filter((row) => row.acceptance?.successCriteria.includes(criterion));
    expect(matchingRows.length).toBeGreaterThan(0);
  });

  it("has positive corpus coverage for every detector-owned reason code", () => {
    const positivelyCoveredCodes = new Set(
      CORPUS.flatMap((row) => row.expectReasons ?? []).filter((code) => detectorOwnedCodes.has(code)),
    );

    expect([...positivelyCoveredCodes].sort()).toEqual([...checkOwnedCodes].sort());
  });

  it("maps detector-family metadata only to CHECKS-owned reason codes", () => {
    const metadataFamilies = new Set(CORPUS.flatMap((row) => row.acceptance?.detectorFamilies ?? []));

    for (const family of metadataFamilies) {
      expect(checkOwnedCodes.has(family), `${family} is not owned by CHECKS`).toBe(true);
    }
  });
});
