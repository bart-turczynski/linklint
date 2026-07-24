import { describe, expect, it } from "vitest";

import {
  assertValidSourceDescriptor,
  createOnlineSecret,
  freshnessFor,
  isOnlineSecret,
  OnlineSourceConfigError,
  preflightOnlineSource,
  REDACTED_SECRET,
  type OnlineSourceDescriptor,
} from "../src/sources/index.js";
import { assertOnlineSourceContract } from "./contract/online-source-contract-kit.js";

/** A live provider that discloses the full URL under a required credential. */
const liveProvider: OnlineSourceDescriptor = {
  id: "rdap.registration-age",
  displayName: "RDAP registration age",
  version: "1.0.0",
  layer: "reputation",
  evidenceScope: ["rdap.domain"],
  disclosure: {
    recipient: "rdap.arin",
    sends: ["registrable-domain"],
    consentRequired: [],
  },
  credentials: { kind: "none" },
  terms: {
    supportedModes: ["non-commercial", "fair-use", "commercial"],
    attributionRequired: false,
    redistribution: "permitted",
    caching: "response-directed",
  },
  dataOrigin: { kind: "live-provider", recipient: "rdap.arin" },
  freshness: { declaresExpiry: true, staleWhenExpired: true },
  scoring: "conjunctive-finding",
  noMatchSemantics: "absence-is-not-safety",
};

/** A full-URL provider gated by explicit consent AND a required BYOK credential. */
const fullUrlProvider: OnlineSourceDescriptor = {
  id: "urlscan.submit",
  displayName: "Full-URL reputation",
  version: "0.1.0",
  layer: "reputation",
  evidenceScope: ["reputation.verdict"],
  disclosure: {
    recipient: "provider.example",
    sends: ["full-url"],
    consentRequired: ["full-url"],
  },
  credentials: { kind: "required", scheme: "bearer", label: "API Key" },
  terms: {
    supportedModes: ["commercial"],
    attributionRequired: true,
    redistribution: "prohibited",
    caching: "prohibited",
  },
  dataOrigin: { kind: "live-provider", recipient: "provider.example" },
  freshness: { declaresExpiry: false, staleWhenExpired: false },
  scoring: "evidence-only",
  noMatchSemantics: "absence-is-not-safety",
};

/** A caller-owned local mirror that discloses nothing at query time. */
const callerMirror: OnlineSourceDescriptor = {
  id: "urlhaus.mirror",
  displayName: "URLhaus caller-owned mirror",
  version: "1.0.0",
  layer: "reputation",
  evidenceScope: ["urlhaus.match"],
  disclosure: { recipient: "local-mirror", sends: ["none"], consentRequired: [] },
  credentials: { kind: "none" },
  terms: {
    supportedModes: ["non-commercial", "fair-use"],
    attributionRequired: true,
    redistribution: "caller-owned-only",
    caching: "permitted",
  },
  dataOrigin: { kind: "caller-owned-mirror", bundled: false },
  freshness: { declaresExpiry: true, staleWhenExpired: true },
  scoring: "conjunctive-finding",
  noMatchSemantics: "absence-is-not-safety",
};

describe("online-source contract kit", () => {
  it("passes the full battery for a live provider disclosing a registrable domain", () => {
    assertOnlineSourceContract(liveProvider);
  });

  it("passes the full battery for a consent-gated full-URL BYOK provider", () => {
    assertOnlineSourceContract(fullUrlProvider, { sampleCredential: "secret-token-123" });
  });

  it("passes the full battery for a caller-owned local mirror", () => {
    assertOnlineSourceContract(callerMirror);
  });
});

describe("descriptor validation", () => {
  it("accepts each reference descriptor", () => {
    for (const descriptor of [liveProvider, fullUrlProvider, callerMirror]) {
      expect(() => assertValidSourceDescriptor(descriptor)).not.toThrow();
    }
  });

  it("rejects a sent consent-gated channel that is not gated", () => {
    const bad: OnlineSourceDescriptor = {
      ...fullUrlProvider,
      disclosure: { recipient: "x", sends: ["full-url"], consentRequired: [] },
    };
    expect(() => assertValidSourceDescriptor(bad)).toThrow(OnlineSourceConfigError);
  });

  it("rejects 'none' combined with another disclosure channel", () => {
    const bad: OnlineSourceDescriptor = {
      ...callerMirror,
      disclosure: { recipient: "x", sends: ["none", "host"], consentRequired: [] },
    };
    expect(() => assertValidSourceDescriptor(bad)).toThrow(/sole channel/);
  });

  it("rejects a mirror that claims to be bundled", () => {
    const bad = {
      ...callerMirror,
      dataOrigin: { kind: "caller-owned-mirror", bundled: true },
    } as unknown as OnlineSourceDescriptor;
    expect(() => assertValidSourceDescriptor(bad)).toThrow(/bundled must be false/);
  });

  it("rejects a wrong no-match honesty pin", () => {
    const bad = {
      ...liveProvider,
      noMatchSemantics: "safe-when-absent",
    } as unknown as OnlineSourceDescriptor;
    expect(() => assertValidSourceDescriptor(bad)).toThrow(/absence-is-not-safety/);
  });
});

describe("terms gate", () => {
  it("throws on an unsupported commercial mode", () => {
    expect(() =>
      preflightOnlineSource(fullUrlProvider, {
        commercialMode: "non-commercial",
        acceptAttribution: true,
        credential: createOnlineSecret("k"),
        consent: { allow: ["full-url"] },
      }),
    ).toThrow(OnlineSourceConfigError);
  });

  it("throws when required attribution is not accepted", () => {
    try {
      preflightOnlineSource(callerMirror, { commercialMode: "fair-use" });
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(OnlineSourceConfigError);
      expect((error as OnlineSourceConfigError).code).toBe("attribution-not-accepted");
    }
  });
});

describe("runtime skip gates", () => {
  it("skips a required-credential source with a machine-readable cause", () => {
    const preflight = preflightOnlineSource(fullUrlProvider, {
      commercialMode: "commercial",
      acceptAttribution: true,
      consent: { allow: ["full-url"] },
    });
    expect(preflight.ok).toBe(false);
    if (!preflight.ok) {
      expect(preflight.cause.code).toBe("credentials-missing");
      expect(preflight.cause.details).toMatchObject({ scheme: "bearer" });
    }
  });

  it("skips when consent for a gated disclosure channel is absent", () => {
    const preflight = preflightOnlineSource(fullUrlProvider, {
      commercialMode: "commercial",
      acceptAttribution: true,
      credential: createOnlineSecret("k"),
    });
    expect(preflight.ok).toBe(false);
    if (!preflight.ok) {
      expect(preflight.cause.code).toBe("disclosure-consent-required");
      expect(preflight.cause.details).toMatchObject({ recipient: "provider.example" });
    }
  });

  it("clears a fully-consented full-URL provider and returns its credential", () => {
    const secret = createOnlineSecret("k");
    const preflight = preflightOnlineSource(fullUrlProvider, {
      commercialMode: "commercial",
      acceptAttribution: true,
      credential: secret,
      consent: { allow: ["full-url"] },
    });
    expect(preflight.ok).toBe(true);
    if (preflight.ok) {
      expect(preflight.credential).toBe(secret);
      expect(preflight.disclosure).toEqual(["full-url"]);
    }
  });
});

describe("BYOK secret redaction", () => {
  it("reveals only through reveal() and redacts every serialization sink", () => {
    const secret = createOnlineSecret("top-secret-value");
    expect(isOnlineSecret(secret)).toBe(true);
    expect(secret.reveal()).toBe("top-secret-value");
    expect(String(secret)).toBe(REDACTED_SECRET);
    expect(JSON.stringify(secret)).toBe(`"${REDACTED_SECRET}"`);
    expect(JSON.stringify({ nested: { secret } })).not.toContain("top-secret-value");
    expect(Object.values(secret).join("")).not.toContain("top-secret-value");
  });

  it("rejects an empty or non-string secret", () => {
    expect(() => createOnlineSecret("")).toThrow(TypeError);
    expect(() => createOnlineSecret(undefined as unknown as string)).toThrow(TypeError);
  });

  it("does not treat a plain object as a secret", () => {
    expect(isOnlineSecret({ reveal: () => "x" })).toBe(false);
    expect(isOnlineSecret(null)).toBe(false);
  });
});

describe("freshness helper", () => {
  const now = new Date("2026-07-24T12:00:00.000Z");

  it("reports unknown when the source cannot declare expiry", () => {
    const result = freshnessFor({ declaresExpiry: false, staleWhenExpired: false }, now, now);
    expect(result).toEqual({ status: "unknown", expiresAt: null });
  });

  it("reports fresh before expiry and stale after", () => {
    const cap = { declaresExpiry: true, staleWhenExpired: true };
    expect(freshnessFor(cap, now, new Date("2026-07-24T13:00:00.000Z")).status).toBe("fresh");
    expect(freshnessFor(cap, now, new Date("2026-07-24T11:00:00.000Z")).status).toBe("stale");
  });

  it("keeps an expired observation fresh when the source does not go stale", () => {
    const cap = { declaresExpiry: true, staleWhenExpired: false };
    expect(freshnessFor(cap, now, new Date("2026-07-24T11:00:00.000Z")).status).toBe("fresh");
  });
});
