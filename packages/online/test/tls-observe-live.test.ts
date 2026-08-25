/**
 * Live coverage for the TLS OBSERVE port (`NodeTlsObserver` in `transport/tls-node.ts`).
 *
 * `LINK-zgmixagu`: the observer used to discount `CERT_HAS_EXPIRED` and
 * `CERT_NOT_YET_VALID` as "validity-only" errors and report the chain as trusted
 * anyway, so that trust and validity would read as independent axes. That inference
 * is not available from a TLS verifier. OpenSSL exposes a SINGLE verification error
 * even when several faults coexist, so the same `CERT_HAS_EXPIRED` code comes back
 * for an expired leaf under a TRUSTED CA and for an expired leaf under an UNTRUSTED
 * one. The old rule marked the second — expired AND untrusted — as trusted.
 *
 * Every fixture case below is therefore stated as an explicit expected
 * (`chainTrusted`, `trustErrorCode`) pair, and the multiple-fault case is asserted to
 * be indistinguishable at the socket from the single-fault one. That indistinguishability
 * is the whole argument for passing the verdict through unmodified.
 *
 * No fixture harness: this drives a real handshake, because the defect lived entirely
 * in how the concrete Node socket verdict was read. The CA is injected with
 * `tls.setDefaultCACertificates()` per case and restored afterwards, so "trusted CA"
 * and "untrusted CA" are the genuine process trust store rather than a flag.
 *
 * Loopback only — no external network.
 */
import { readFileSync } from "node:fs";
import { createServer as createTlsServer, type Server as TlsServer } from "node:https";
import { dirname, join } from "node:path";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { normalizeTlsCertificate } from "../src/transport/tls-certificate.js";
import { NodeTlsObserver } from "../src/transport/tls-node.js";
import type { TlsHandshakeObservation } from "../src/transport/tls-types.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "tls");
const pem = (name: string) => readFileSync(join(FIXTURES, name), "utf8");

const CA = pem("ca.cert.pem");
const SERVER_NAME = "origin.example";

/** The process trust store as it was before this file touched it. */
const ORIGINAL_CAS = getCACertificates("default");

// A list, not a single handle: the indistinguishability case starts two servers.
const servers: TlsServer[] = [];

afterEach(async () => {
  setDefaultCACertificates([...ORIGINAL_CAS]);
  const running = servers.splice(0, servers.length);
  for (const one of running) {
    // close() alone waits for lingering sockets; the observer destroys its socket
    // immediately, but a half-closed handshake could otherwise hold this open.
    one.closeAllConnections();
    await new Promise<void>((resolve) => one.close(() => resolve()));
  }
});

/**
 * Serve `<prefix>.cert.pem` on loopback and observe it, with the fixture CA either in
 * the default trust store or absent from it.
 */
async function observe(prefix: string, options: { trustCa: boolean }): Promise<TlsHandshakeObservation> {
  const created = createTlsServer(
    { key: pem(`${prefix}.key.pem`), cert: pem(`${prefix}.cert.pem`) },
    (_req, res) => res.end("unreachable: observe sends no HTTP"),
  );
  created.on("tlsClientError", () => undefined);
  servers.push(created);
  await new Promise<void>((resolve) => created.listen(0, "127.0.0.1", () => resolve()));
  const address = created.address();
  if (address === null || typeof address === "string") throw new Error("no port");

  setDefaultCACertificates(options.trustCa ? [...ORIGINAL_CAS, CA] : [...ORIGINAL_CAS]);
  return new NodeTlsObserver().observe({
    hostname: SERVER_NAME,
    address: "127.0.0.1",
    port: address.port,
    serverName: SERVER_NAME,
  });
}

/**
 * The three axes as the pipeline reports them, at the real observation instant.
 *
 * Not a frozen date: the long-lived fixtures take their `notBefore` from whenever
 * `generate.sh` last ran, so any hardcoded instant silently turns them `not-yet-valid`
 * after the next regeneration. `expired` closed its window on 2020-01-02 and the
 * others run ~100 years, so wall-clock time separates them for the life of the repo.
 */
function validationNow(observation: TlsHandshakeObservation) {
  return normalizeTlsCertificate(observation, {
    hostname: SERVER_NAME,
    observedAt: new Date(),
  }).validation;
}

describe("NodeTlsObserver — chain trust is the verifier's verdict (LINK-zgmixagu)", () => {
  it("reports a valid chain under a trusted CA as trusted, with no defects", async () => {
    const observation = await observe("valid", { trustCa: true });
    expect(observation.chainTrusted).toBe(true);
    expect(observation.trustErrorCode).toBeNull();
    expect(validationNow(observation)).toMatchObject({
      chainTrusted: true,
      hostnameMatch: true,
      withinValidity: true,
      defects: [],
    });
  });

  it("reports a valid chain under an UNTRUSTED CA as untrusted", async () => {
    // Single fault, and the code names it: the leaf's signer is not reachable from
    // the trust store. Nothing about validity is in question here.
    const observation = await observe("valid", { trustCa: false });
    expect(observation.chainTrusted).toBe(false);
    expect(observation.trustErrorCode).toBe("UNABLE_TO_VERIFY_LEAF_SIGNATURE");
    expect(validationNow(observation)).toMatchObject({
      chainTrusted: false,
      hostnameMatch: true,
      withinValidity: true,
      defects: ["untrusted"],
    });
  });

  it("reports an untrusted self-signed leaf as untrusted and self-signed", async () => {
    const observation = await observe("untrusted", { trustCa: false });
    expect(observation.chainTrusted).toBe(false);
    expect(observation.trustErrorCode).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
    expect(validationNow(observation).defects).toEqual(
      expect.arrayContaining(["untrusted", "self-signed"]),
    );
  });

  it("keeps hostname identity out of the socket verdict", async () => {
    // Correctly signed by the trusted CA, in date, but for `other.example`. The
    // observer's no-op checkServerIdentity means the socket still authorizes; the
    // mismatch is recomputed downstream from the DER. This is the one axis a socket
    // verdict CAN be separated from, and it stays separated.
    const observation = await observe("wrong-name", { trustCa: true });
    expect(observation.chainTrusted).toBe(true);
    expect(observation.trustErrorCode).toBeNull();
    expect(validationNow(observation)).toMatchObject({
      chainTrusted: true,
      hostnameMatch: false,
      withinValidity: true,
      defects: ["hostname-mismatch"],
    });
  });

  it("reports a SINGLE-fault expired leaf under a trusted CA as untrusted, expired", async () => {
    // Only the validity window is wrong. The verifier still refuses to certify the
    // chain, so `chainTrusted` is false — and `expired` is computed independently
    // from the leaf's own notAfter, not from this code.
    const observation = await observe("expired", { trustCa: true });
    expect(observation.chainTrusted).toBe(false);
    expect(observation.trustErrorCode).toBe("CERT_HAS_EXPIRED");
    expect(validationNow(observation)).toMatchObject({
      chainTrusted: false,
      hostnameMatch: true,
      withinValidity: false,
    });
    expect(validationNow(observation).defects).toEqual(
      expect.arrayContaining(["expired", "untrusted"]),
    );
  });

  it("MULTIPLE FAULTS: an expired leaf under an UNTRUSTED CA is not reported as trusted", async () => {
    // The regression. Expired AND unrooted, and the socket says only CERT_HAS_EXPIRED.
    const observation = await observe("expired", { trustCa: false });
    expect(observation.trustErrorCode).toBe("CERT_HAS_EXPIRED");
    expect(observation.chainTrusted).toBe(false);
    expect(validationNow(observation).defects).toEqual(
      expect.arrayContaining(["expired", "untrusted"]),
    );
  });

  it("exposes the same verdict for one fault and for two, which is why it cannot be discounted", async () => {
    // Stated as one assertion so the ambiguity is pinned rather than implied by two
    // tests that happen to agree: if a future change could tell these apart, it would
    // have to break this equality first.
    const trustedCa = await observe("expired", { trustCa: true });
    const untrustedCa = await observe("expired", { trustCa: false });
    expect({
      chainTrusted: untrustedCa.chainTrusted,
      trustErrorCode: untrustedCa.trustErrorCode,
    }).toEqual({ chainTrusted: trustedCa.chainTrusted, trustErrorCode: trustedCa.trustErrorCode });
    expect(trustedCa.trustErrorCode).toBe("CERT_HAS_EXPIRED");
    expect(trustedCa.chainTrusted).toBe(false);
  });
});

/**
 * The second defect this file pins is not about certificates at all.
 *
 * `NodeTlsObserver.observe` calls `tls.connect` BARE inside a `new Promise`
 * executor and attaches its `fail` mapper only afterwards. `tls.connect`
 * validates its options inside the socket constructor and THROWS rather than
 * emitting `error`, so a refused option escapes before any listener exists and
 * the executor turns it into a rejection carrying a raw Node error — untyped at
 * this port. That is the same shape `transport/node.ts` fixed in
 * `NodeConnectionPorts.request` and `openSocket`, and it is pinned here the way
 * `test/node-transport-headers.test.ts` pins `openSocket`: at the port surface,
 * where an out-of-range port IS reachable.
 *
 * The trigger opens NO socket and contacts NO peer — `tls.connect` refuses the
 * port inside its own constructor, so nothing leaves the process.
 */
describe("NodeTlsObserver — synchronous connect throws", () => {
  it("types a connect option Node refuses synchronously", async () => {
    const failure = await rejectionOf(
      new NodeTlsObserver().observe({
        hostname: SERVER_NAME,
        address: "127.0.0.1",
        // Out of range, so `tls.connect` throws `ERR_SOCKET_BAD_PORT` from the
        // constructor. Nothing is ever sent, and no peer is contacted.
        port: 99_999,
        serverName: SERVER_NAME,
      }),
    );

    expect(failure.name).toBe("NodeTlsObserveFailure");
    expect(failure.code).toBe("connect-error");
  });
});

async function rejectionOf(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    const failure = error as { name?: unknown; code?: unknown; message?: unknown };
    return {
      name: typeof failure.name === "string" ? failure.name : "",
      code: failure.code,
      message: typeof failure.message === "string" ? failure.message : "",
    };
  }
  throw new Error("expected a rejection");
}
