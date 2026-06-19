import { describe, expect, it } from "vitest";
import { CORPUS } from "./corpus.js";
import { checkRow } from "./harness.js";

// D1 — every labeled corpus row conforms to its expected behavior.
describe("labeled corpus conformance", () => {
  it.each(CORPUS.map((row) => [row.input || "(empty)", row] as const))(
    "%s",
    (_label, row) => {
      const { ok, failures } = checkRow(row);
      expect(ok, `${row.input} (${row.label}): ${failures.join("; ")}`).toBe(true);
    },
  );
});
