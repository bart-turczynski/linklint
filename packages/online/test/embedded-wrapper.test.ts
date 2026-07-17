import {
  ENRICHMENT_SCHEMA_VERSION,
  inspect,
  inspectAsync,
  isEnrichmentReport,
} from "linklint";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  EMBEDDED_WRAPPER_SOURCE_ID,
  MAX_EMBEDDED_WRAPPER_DEPTH,
  createEmbeddedWrapperEnricher,
  decodeEmbeddedWrapper,
} from "../src/resolution/index.js";

const OBSERVED_AT = "2026-07-17T12:00:00.000Z";
const fixedNow = () => new Date(OBSERVED_AT);

const safeLink = (destination: string): string =>
  `https://nam01.safelinks.protection.outlook.com/?url=${encodeURIComponent(destination)}` +
  "&data=05%7C01&reserved=0";

const proofpointV2 = (destination: string): string => {
  const encoded = encodeURIComponent(destination)
    .replaceAll("%2F", "_")
    .replaceAll("%", "-");
  return `https://urldefense.proofpoint.com/v2/url?u=${encoded}&d=DwMFaQ&c=cluster&e=`;
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("L2 local embedded-wrapper decoding", () => {
  it("decodes the exact Microsoft Safe Links standard host and url parameter once", () => {
    const destination = "https://example.com/a?x=one+two&y=%25done";
    expect(decodeEmbeddedWrapper(safeLink(destination))).toEqual({
      status: "decoded",
      wrapperUrl: safeLink(destination),
      destinationUrl: destination,
      vendor: "microsoft-safe-links",
      format: "microsoft-safe-links-standard",
      formatVersion: "standard-2026-07",
    });

    const multiplyEncoded =
      "https://nam01.safelinks.protection.outlook.com/?url=https%253A%252F%252Fexample.com";
    expect(decodeEmbeddedWrapper(multiplyEncoded)).toMatchObject({
      status: "malformed",
      cause: { code: "invalid-decoded-url" },
    });
  });

  it("decodes Proofpoint's documented v1, v2, and v3 examples", () => {
    const v1 =
      "https://urldefense.proofpoint.com/v1/url?u=http%3A%2F%2Fwww.bouncycastle.org%2F&k=signature";
    expect(decodeEmbeddedWrapper(v1)).toMatchObject({
      status: "decoded",
      destinationUrl: "http://www.bouncycastle.org/",
      format: "proofpoint-url-defense-v1",
      formatVersion: "v1",
    });
    expect(
      decodeEmbeddedWrapper(
        "https://urldefense.proofpoint.com/v1/url?" +
          "u=https%3A%2F%2Fexample.com%2Fsearch%3Fq%3Da+b%26amp%3Bx%3D1&k=signature",
      ),
    ).toMatchObject({
      status: "decoded",
      destinationUrl: "https://example.com/search?q=a+b&x=1",
    });

    const v2 =
      "https://urldefense.proofpoint.com/v2/url?" +
      "u=https-3A__media.mnn.com_assets_images_2016_06_jupiter-2Dnasa.jpg.638x0-5Fq80-5Fcrop-2Dsmart.jpg" +
      "&d=DwMBaQ&c=cluster&e=";
    expect(decodeEmbeddedWrapper(v2)).toMatchObject({
      status: "decoded",
      destinationUrl:
        "https://media.mnn.com/assets/images/2016/06/jupiter-nasa.jpg.638x0_q80_crop-smart.jpg",
      format: "proofpoint-url-defense-v2",
      formatVersion: "v2",
    });

    const v3 =
      "https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;" +
      "Kw!-612Flbf0JvQ3kNJkRi5Jg!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$";
    expect(decodeEmbeddedWrapper(v3)).toMatchObject({
      status: "decoded",
      destinationUrl: "https://google.com:443/search?q=a+test&gs=ps",
      format: "proofpoint-url-defense-v3",
      formatVersion: "v3.0.1",
    });
  });

  it("implements the pinned v3 run-token grammar and exact replacement consumption", () => {
    expect(
      decodeEmbeddedWrapper(
        "https://urldefense.proofpoint.com/v3/__https://example.com/a**A__;eHk!tracking$",
      ),
    ).toMatchObject({
      status: "decoded",
      destinationUrl: "https://example.com/axy",
    });

    expect(
      decodeEmbeddedWrapper("https://urldefense.com/v3/__https://example.com/a*__;!tracking$"),
    ).toMatchObject({ status: "malformed", cause: { code: "malformed-wrapper" } });
    expect(
      decodeEmbeddedWrapper("https://urldefense.com/v3/__https://example.com/a__;YQ!tracking$"),
    ).toMatchObject({ status: "malformed", cause: { code: "malformed-wrapper" } });
    expect(
      decodeEmbeddedWrapper("https://urldefense.com/v3/__https://example.com/a*__;a!tracking$"),
    ).toMatchObject({ status: "malformed", cause: { code: "malformed-wrapper" } });
  });

  it("matches only exact trusted hosts and leaves opaque shorteners to L1", () => {
    for (const input of [
      "https://nam01.safelinks.protection.outlook.com.evil.test/?url=https://example.com",
      "https://extra.nam01.safelinks.protection.outlook.com/?url=https://example.com",
      "https://urldefense.proofpoint.com.evil.test/v2/url?u=https-3A__example.com&d=x",
      "https://bit.ly/opaque",
      "https://t.co/opaque",
      "https://lnkd.in/opaque",
    ]) {
      expect(decodeEmbeddedWrapper(input)).toEqual({ status: "not-wrapper", input });
    }
  });

  it("distinguishes unsupported trusted formats from malformed supported formats", () => {
    expect(
      decodeEmbeddedWrapper("https://urldefense.proofpoint.com/v4/url?u=https://example.com"),
    ).toMatchObject({
      status: "unsupported",
      vendor: "proofpoint-url-defense",
      cause: { code: "unsupported-wrapper-format" },
    });
    expect(
      decodeEmbeddedWrapper("http://nam01.safelinks.protection.outlook.com/?url=https://example.com"),
    ).toMatchObject({
      status: "unsupported",
      vendor: "microsoft-safe-links",
    });
    expect(
      decodeEmbeddedWrapper(
        "https://nam01.safelinks.protection.outlook.com/?url=https://one.example&url=https://two.example",
      ),
    ).toMatchObject({
      status: "malformed",
      vendor: "microsoft-safe-links",
      cause: { code: "malformed-wrapper" },
    });
    expect(
      decodeEmbeddedWrapper("https://urldefense.proofpoint.com/v2/url?u=https-3X__example.com&d=x"),
    ).toMatchObject({
      status: "malformed",
      format: "proofpoint-url-defense-v2",
      cause: { code: "malformed-wrapper" },
    });
  });

  it("applies a mandatory decoded-length bound with safe invalid-option fallback", () => {
    const wrapper = safeLink("https://example.com/a-long-path");
    expect(decodeEmbeddedWrapper(wrapper, { maxUrlLength: 12 })).toMatchObject({
      status: "malformed",
      cause: { code: "decoded-url-too-long" },
    });
    expect(decodeEmbeddedWrapper(wrapper, { maxUrlLength: 0 }).status).toBe("decoded");
  });
});

describe("L2 structured wrapper enricher", () => {
  it("decodes nested wrappers, re-inspects every target offline, and projects destination findings", async () => {
    const destination = "https://paypa1.com/secure/login";
    const proofpoint = proofpointV2(destination);
    const input = safeLink(proofpoint);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const result = await inspectAsync(input, {
      enrichers: [createEmbeddedWrapperEnricher({ now: fixedNow })],
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.enrichment?.schemaVersion).toBe(ENRICHMENT_SCHEMA_VERSION);
    expect(isEnrichmentReport(result.enrichment, {
      sourceId: EMBEDDED_WRAPPER_SOURCE_ID,
      layer: "resolution",
    })).toBe(true);
    expect(result.enrichment?.outcomes).toHaveLength(2);
    expect(result.enrichment?.outcomes.map((outcome) => outcome.status)).toEqual([
      "success",
      "success",
    ]);
    expect(result.enrichment?.outcomes.map((outcome) => outcome.subject.value)).toEqual([
      proofpoint,
      destination,
    ]);
    expect(result.enrichment?.outcomes.every((outcome) => outcome.observedAt === OBSERVED_AT))
      .toBe(true);

    const finalOutcome = result.enrichment?.outcomes[1];
    expect(finalOutcome?.evidence[0]?.type).toBe("wrapper.decode");
    expect(finalOutcome?.evidence[0]?.payload).toMatchObject({
      destinationUrl: destination,
      depth: 2,
      localOnly: true,
      offlineInspection: {
        status: "ok",
        reasonCodes: inspect(destination).reasons.map((reason) => reason.code),
      },
    });
    expect(finalOutcome?.findings.map((finding) => finding.code)).toEqual(
      inspect(destination).reasons.map((reason) => reason.code),
    );
    expect(result.reasons.map((reason) => reason.code)).toContain("brand_homoglyph");
    expect(result.checksRun).toContain(`resolution:${EMBEDDED_WRAPPER_SOURCE_ID}`);
  });

  it("reports ordinary URLs as no-hit without claiming safety", async () => {
    const input = "https://bit.ly/opaque";
    const result = await inspectAsync(input, {
      enrichers: [createEmbeddedWrapperEnricher({ now: fixedNow })],
    });
    expect(result.enrichment?.outcomes).toEqual([
      expect.objectContaining({
        status: "no-hit",
        subject: { kind: "url", value: input },
        evidence: [],
        findings: [],
      }),
    ]);
    expect(result.checksRun).toContain(`resolution:${EMBEDDED_WRAPPER_SOURCE_ID}`);
    expect(result.checksSkipped).not.toContain(`resolution:${EMBEDDED_WRAPPER_SOURCE_ID}`);
  });

  it("maps unsupported, malformed, and depth-limited states without throwing", async () => {
    const unsupported = await inspectAsync(
      "https://urldefense.proofpoint.com/v9/url?u=https://example.com",
      { enrichers: [createEmbeddedWrapperEnricher({ now: fixedNow })] },
    );
    expect(unsupported.enrichment?.outcomes[0]).toMatchObject({
      status: "skipped",
      cause: { code: "unsupported-wrapper-format", retryable: false },
    });

    const malformed = await inspectAsync(
      "https://nam01.safelinks.protection.outlook.com/?data=missing-url",
      { enrichers: [createEmbeddedWrapperEnricher({ now: fixedNow })] },
    );
    expect(malformed.enrichment?.outcomes[0]).toMatchObject({
      status: "failure",
      cause: { code: "malformed-wrapper", retryable: false },
    });

    const nested = safeLink(proofpointV2("https://example.com/final"));
    const limited = await inspectAsync(nested, {
      enrichers: [createEmbeddedWrapperEnricher({ maxDepth: 1, now: fixedNow })],
    });
    expect(limited.enrichment?.outcomes.map((outcome) => outcome.status)).toEqual([
      "success",
      "failure",
    ]);
    expect(limited.enrichment?.outcomes[1]).toMatchObject({
      subject: { kind: "url", value: proofpointV2("https://example.com/final") },
      cause: { code: "wrapper-depth-exceeded", details: { maxDepth: 1 } },
    });
    expect(limited.checksRun).toContain(`resolution:${EMBEDDED_WRAPPER_SOURCE_ID}`);
    expect(limited.checksSkipped).toContain(`resolution:${EMBEDDED_WRAPPER_SOURCE_ID}`);
  });

  it("caps caller depth and emits an explicit cancellation skip", async () => {
    let deeplyNested = "https://example.com/final";
    for (let depth = 0; depth < MAX_EMBEDDED_WRAPPER_DEPTH + 1; depth += 1) {
      deeplyNested = safeLink(deeplyNested);
    }
    const capped = await inspectAsync(deeplyNested, {
      enrichers: [createEmbeddedWrapperEnricher({
        maxDepth: MAX_EMBEDDED_WRAPPER_DEPTH + 100,
        now: fixedNow,
      })],
    });
    expect(capped.enrichment?.outcomes).toHaveLength(MAX_EMBEDDED_WRAPPER_DEPTH + 1);
    expect(capped.enrichment?.outcomes.at(-1)).toMatchObject({
      status: "failure",
      cause: {
        code: "wrapper-depth-exceeded",
        details: { maxDepth: MAX_EMBEDDED_WRAPPER_DEPTH },
      },
    });

    const controller = new AbortController();
    controller.abort();
    const cancelled = await inspectAsync(safeLink("https://example.com"), {
      signal: controller.signal,
      enrichers: [createEmbeddedWrapperEnricher({
        maxDepth: MAX_EMBEDDED_WRAPPER_DEPTH + 100,
        now: fixedNow,
      })],
    });
    expect(cancelled.enrichment?.outcomes[0]).toMatchObject({
      status: "skipped",
      cause: { code: "caller-aborted" },
    });
  });
});
