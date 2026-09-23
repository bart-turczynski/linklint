import { describe, expect, it } from "vitest";
import {
  ENRICHMENT_SCHEMA_VERSION,
  inspect,
  inspectAsync,
  type Enricher,
  type EnricherFinding,
  type EnrichmentEvidence,
  type EnrichmentLayer,
  type EnrichmentOutcome,
  type EnrichmentPlan,
  type EnrichmentReport,
  type EnrichmentSubject,
} from "../src/index.js";

/** K7 deterministic, zero-network staged-orchestration contract fixtures. */

const ORIGINAL = "https://www.example.com/start";
const DESTINATION = "https://landing.example.org/finish";
const OBSERVED_AT = "2026-07-17T12:00:00.000Z";
const PROVENANCE = {
  kind: "declared",
  source: { name: "orchestration.fixture", version: "1.0.0" },
  data: { name: "orchestration-fixtures", version: "2026-07-17" },
} as const;
const FRESHNESS = { status: "fresh", expiresAt: "2026-07-18T12:00:00.000Z" } as const;

function report(...outcomes: EnrichmentOutcome[]): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes };
}

function outcomeBase(
  sourceId: string,
  layer: EnrichmentLayer,
  subject: EnrichmentSubject,
) {
  return {
    sourceId,
    layer,
    subject,
    observedAt: OBSERVED_AT,
    provenance: PROVENANCE,
    freshness: FRESHNESS,
  } as const;
}

function noHit(
  sourceId: string,
  layer: EnrichmentLayer,
  subject: EnrichmentSubject = { kind: "url", value: ORIGINAL },
): EnrichmentOutcome {
  return {
    ...outcomeBase(sourceId, layer, subject),
    status: "no-hit",
    evidence: [],
    findings: [],
  };
}

function success(
  sourceId: string,
  layer: EnrichmentLayer,
  subject: EnrichmentSubject,
  findings: EnricherFinding[],
  evidence: EnrichmentEvidence[] = [],
): EnrichmentOutcome {
  return {
    ...outcomeBase(sourceId, layer, subject),
    status: "success",
    evidence,
    findings,
  };
}

describe("K7 — sequential outcomes become downstream input", () => {
  it("runs a dependent destination check only after redirect evidence is available", async () => {
    const calls: string[] = [];
    const redirect: Enricher = {
      id: "redirect.fixture",
      layer: "resolution",
      async enrich(_base, ctx) {
        calls.push("redirect");
        expect(ctx.previousOutcomes).toEqual([]);
        return report(
          success(
            "redirect.fixture",
            "resolution",
            { kind: "url", value: ORIGINAL },
            [],
            [
              {
                type: "http.redirect",
                subject: { kind: "url", value: DESTINATION },
                observedAt: OBSERVED_AT,
                provenance: PROVENANCE,
                freshness: FRESHNESS,
                payload: { statusCode: 302, hop: 1, location: DESTINATION },
              },
            ],
          ),
        );
      },
    };
    const destinationReputation: Enricher = {
      id: "destination.fixture",
      layer: "reputation",
      dependsOn: ["resolution:redirect.fixture"],
      async enrich(base, ctx) {
        calls.push("destination");
        expect(base.input).toBe(ORIGINAL);
        expect(Object.isFrozen(ctx.previousOutcomes)).toBe(true);
        expect(ctx.previousOutcomes).toHaveLength(1);
        expect(ctx.previousOutcomes[0]?.evidence[0]?.subject).toEqual({
          kind: "url",
          value: DESTINATION,
        });
        return report(
          noHit("destination.fixture", "reputation", {
            kind: "url",
            value: DESTINATION,
          }),
        );
      },
    };
    const plan = [redirect, destinationReputation] satisfies EnrichmentPlan;

    const result = await inspectAsync(ORIGINAL, { enrichers: plan });

    expect(calls).toEqual(["redirect", "destination"]);
    expect(result.enrichment?.outcomes.map((item) => item.sourceId)).toEqual([
      "redirect.fixture",
      "destination.fixture",
    ]);
    expect(result.checksRun).toEqual(
      expect.arrayContaining([
        "resolution:redirect.fixture",
        "reputation:destination.fixture",
      ]),
    );
  });
});

describe("K7 — deterministic fan-out/fan-in stages", () => {
  async function runFanout(completionOrder: "left-first" | "right-first") {
    let releaseLeft!: () => void;
    let releaseRight!: () => void;
    let started = 0;
    let resolveStarted!: () => void;
    const bothStarted = new Promise<void>((resolve) => {
      resolveStarted = resolve;
    });
    const leftGate = new Promise<void>((resolve) => {
      releaseLeft = resolve;
    });
    const rightGate = new Promise<void>((resolve) => {
      releaseRight = resolve;
    });
    const events: string[] = [];

    const root: Enricher = {
      id: "root.fixture",
      layer: "resolution",
      async enrich() {
        events.push("root");
        return report(noHit("root.fixture", "resolution"));
      },
    };
    const left: Enricher = {
      id: "left.fixture",
      layer: "reputation",
      dependsOn: ["resolution:root.fixture"],
      async enrich() {
        events.push("left:start");
        started += 1;
        if (started === 2) resolveStarted();
        await leftGate;
        events.push("left:end");
        return report(noHit("left.fixture", "reputation"));
      },
    };
    const right: Enricher = {
      id: "right.fixture",
      layer: "resolution",
      dependsOn: ["resolution:root.fixture"],
      async enrich() {
        events.push("right:start");
        started += 1;
        if (started === 2) resolveStarted();
        await rightGate;
        events.push("right:end");
        return report(noHit("right.fixture", "resolution"));
      },
    };
    const fanIn: Enricher = {
      id: "fan-in.fixture",
      layer: "reputation",
      dependsOn: ["reputation:left.fixture", "resolution:right.fixture"],
      async enrich(_base, ctx) {
        events.push("fan-in");
        expect(ctx.previousOutcomes.map((item) => item.sourceId)).toEqual([
          "root.fixture",
          "left.fixture",
          "right.fixture",
        ]);
        return report(noHit("fan-in.fixture", "reputation"));
      },
    };

    const pending = inspectAsync(ORIGINAL, {
      enrichers: [root, left, right, fanIn],
    });
    await bothStarted;
    expect(events).toEqual(["root", "left:start", "right:start"]);
    if (completionOrder === "left-first") {
      releaseLeft();
      await Promise.resolve();
      releaseRight();
    } else {
      releaseRight();
      await Promise.resolve();
      releaseLeft();
    }
    return { events, result: await pending };
  }

  it("runs independent fan-out concurrently, waits at fan-in, and serializes in plan order", async () => {
    const leftFirst = await runFanout("left-first");
    const rightFirst = await runFanout("right-first");

    expect(leftFirst.events.at(-1)).toBe("fan-in");
    expect(rightFirst.events.at(-1)).toBe("fan-in");
    expect(leftFirst.result.enrichment?.outcomes.map((item) => item.sourceId)).toEqual([
      "root.fixture",
      "left.fixture",
      "right.fixture",
      "fan-in.fixture",
    ]);
    expect(JSON.stringify(leftFirst.result.enrichment)).toBe(
      JSON.stringify(rightFirst.result.enrichment),
    );
  });
});

describe("K7 — unavailable prerequisites and cancellation stay distinct", () => {
  it("does not invoke a dependent after a failed prerequisite", async () => {
    let dependentCalls = 0;
    const failed: Enricher = {
      id: "failed.fixture",
      layer: "resolution",
      async enrich() {
        throw new Error("fixture failure");
      },
    };
    const dependent: Enricher = {
      id: "dependent.fixture",
      layer: "reputation",
      dependsOn: ["resolution:failed.fixture"],
      async enrich() {
        dependentCalls += 1;
        return report(noHit("dependent.fixture", "reputation"));
      },
    };

    const result = await inspectAsync(ORIGINAL, { enrichers: [failed, dependent] });
    const [failedOutcome, dependentOutcome] = result.enrichment?.outcomes ?? [];

    expect(dependentCalls).toBe(0);
    expect(failedOutcome?.status).toBe("failure");
    expect(failedOutcome?.status === "failure" ? failedOutcome.cause.code : null).toBe(
      "source-error",
    );
    expect(dependentOutcome?.status).toBe("skipped");
    expect(
      dependentOutcome?.status === "skipped" ? dependentOutcome.cause : null,
    ).toMatchObject({
      code: "prerequisite-unavailable",
      details: { prerequisites: ["resolution:failed.fixture"] },
    });
    expect(result.checksSkipped).toEqual(
      expect.arrayContaining([
        "resolution:failed.fixture",
        "reputation:dependent.fixture",
      ]),
    );
  });

  it("reports caller cancellation directly for current and future stages", async () => {
    const controller = new AbortController();
    let dependentCalls = 0;
    let rootStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      rootStarted = resolve;
    });
    const root: Enricher = {
      id: "cancel.fixture",
      layer: "resolution",
      enrich() {
        rootStarted();
        return new Promise<EnrichmentReport>(() => {});
      },
    };
    const dependent: Enricher = {
      id: "after-cancel.fixture",
      layer: "reputation",
      dependsOn: ["resolution:cancel.fixture"],
      async enrich() {
        dependentCalls += 1;
        return report(noHit("after-cancel.fixture", "reputation"));
      },
    };

    const pending = inspectAsync(ORIGINAL, {
      enrichers: [root, dependent],
      signal: controller.signal,
    });
    await started;
    controller.abort();
    const result = await pending;

    expect(dependentCalls).toBe(0);
    expect(
      result.enrichment?.outcomes.map((item) =>
        item.status === "skipped" || item.status === "failure" ? item.cause.code : null,
      ),
    ).toEqual(["caller-aborted", "caller-aborted"]);
  });

  it("detects dependency cycles without invoking either source", async () => {
    let calls = 0;
    const a: Enricher = {
      id: "cycle-a.fixture",
      layer: "resolution",
      dependsOn: ["reputation:cycle-b.fixture"],
      async enrich() {
        calls += 1;
        return report(noHit("cycle-a.fixture", "resolution"));
      },
    };
    const b: Enricher = {
      id: "cycle-b.fixture",
      layer: "reputation",
      dependsOn: ["resolution:cycle-a.fixture"],
      async enrich() {
        calls += 1;
        return report(noHit("cycle-b.fixture", "reputation"));
      },
    };

    const result = await inspectAsync(ORIGINAL, { enrichers: [a, b] });

    expect(calls).toBe(0);
    expect(
      result.enrichment?.outcomes.map((item) =>
        item.status === "skipped" ? item.cause.code : null,
      ),
    ).toEqual(["dependency-cycle", "dependency-cycle"]);
  });
});

describe("K7 — suppression follows each structured finding subject", () => {
  it("does not let an original-host rule suppress a discovered destination", async () => {
    // Fixture code is any 0.20 scoring code; `ip_private` served until
    // LINK-bwqhvjcs put it at weight 0 (architecture §6.1.10).
    const subjectAware: Enricher = {
      id: "subjects.fixture",
      layer: "resolution",
      async enrich() {
        return report(
          success(
            "subjects.fixture",
            "resolution",
            { kind: "host", value: "www.example.com" },
            [{ code: "ascii_homoglyph", detail: "original-host finding" }],
          ),
          success(
            "subjects.fixture",
            "resolution",
            { kind: "url", value: DESTINATION },
            [{ code: "ascii_homoglyph", detail: "destination-host finding" }],
          ),
        );
      },
    };

    const result = await inspectAsync(ORIGINAL, {
      enrichers: [subjectAware],
      suppressReasons: [{ code: "ascii_homoglyph", host: "example.com" }],
    });
    const original = result.reasons.find((item) => item.detail === "original-host finding");
    const destination = result.reasons.find(
      (item) => item.detail === "destination-host finding",
    );

    expect(original).toMatchObject({ suppressed: true, weight: 0 });
    expect(destination?.suppressed).toBeUndefined();
    expect(destination?.weight).toBe(0.2);
    expect(result.score).toBeCloseTo(0.2, 10);
  });

  it("preserves the synchronous and no-configured-work invariant", async () => {
    expect(await inspectAsync(ORIGINAL)).toEqual(inspect(ORIGINAL));
    expect(await inspectAsync(ORIGINAL, { enrichers: [] })).toEqual(inspect(ORIGINAL));
  });
});
