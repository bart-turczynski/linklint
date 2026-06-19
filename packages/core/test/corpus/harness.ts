import { inspect, type InspectResult, type Severity } from "../../src/index.js";
import { CORPUS, type CorpusRow } from "./corpus.js";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityAtLeast(actual: Severity, min: Severity): boolean {
  return SEVERITY_RANK[actual] >= SEVERITY_RANK[min];
}

export interface RowCheck {
  row: CorpusRow;
  result: InspectResult;
  ok: boolean;
  failures: string[];
}

/** Check a single corpus row against its expected behavior. */
export function checkRow(row: CorpusRow): RowCheck {
  const result = inspect(row.input);
  const failures: string[] = [];
  const codes = result.reasons.map((r) => r.code);

  switch (row.label) {
    case "deceptive": {
      if (result.status !== "ok") failures.push(`status ${result.status}, expected ok`);
      if ((result.score ?? 0) <= 0) failures.push("score 0, expected > 0");
      const min = row.minSeverity ?? "medium";
      if (result.severity && !severityAtLeast(result.severity, min)) {
        failures.push(`severity ${result.severity}, expected >= ${min}`);
      }
      break;
    }
    case "benign":
    case "info": {
      if (result.status !== "ok") failures.push(`status ${result.status}, expected ok`);
      if (result.score !== 0) failures.push(`score ${result.score}, expected 0`);
      if (result.severity !== "info") failures.push(`severity ${result.severity}, expected info`);
      break;
    }
    case "invalid": {
      if (result.status !== "invalid") failures.push(`status ${result.status}, expected invalid`);
      break;
    }
  }

  for (const code of row.expectReasons ?? []) {
    if (!codes.includes(code)) failures.push(`missing reason '${code}'`);
  }
  for (const code of row.forbidReasons ?? []) {
    if (codes.includes(code)) failures.push(`unexpected reason '${code}'`);
  }

  return { row, result, ok: failures.length === 0, failures };
}

export interface HarnessSummary {
  total: number;
  /** Deceptive rows correctly flagged (score > 0). */
  truePositives: number;
  /** Deceptive rows missed (score 0). */
  falseNegatives: number;
  /** Benign/info rows wrongly flagged (score > 0) — must be zero (SC-2). */
  falsePositives: number;
  /** Benign/info rows correctly left at score 0. */
  trueNegatives: number;
  precision: number;
  recall: number;
  /** Rows whose flag-direction was wrong. */
  falsePositiveInputs: string[];
  falseNegativeInputs: string[];
}

/** Run the full corpus and compute precision/recall over the flag decision. */
export function runHarness(rows: CorpusRow[] = CORPUS): HarnessSummary {
  let tp = 0;
  let fn = 0;
  let fp = 0;
  let tn = 0;
  const falsePositiveInputs: string[] = [];
  const falseNegativeInputs: string[] = [];

  for (const row of rows) {
    const result = inspect(row.input);
    const flagged = result.status === "ok" && (result.score ?? 0) > 0;
    if (row.label === "deceptive") {
      if (flagged) tp++;
      else {
        fn++;
        falseNegativeInputs.push(row.input);
      }
    } else if (row.label === "benign" || row.label === "info") {
      if (flagged) {
        fp++;
        falsePositiveInputs.push(row.input);
      } else tn++;
    }
    // invalid rows are neither positive nor negative for P/R.
  }

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);

  return {
    total: rows.length,
    truePositives: tp,
    falseNegatives: fn,
    falsePositives: fp,
    trueNegatives: tn,
    precision,
    recall,
    falsePositiveInputs,
    falseNegativeInputs,
  };
}
