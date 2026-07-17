import { Buffer } from "node:buffer";

import {
  ENRICHMENT_SCHEMA_VERSION,
  REASON_CODES,
  inspect,
  type EnricherFinding,
  type EnrichmentFreshness,
  type EnrichmentOutcome,
  type EnrichmentPayload,
  type EnrichmentProvenance,
  type EnrichmentReport,
  type EnrichmentSubject,
  type InspectResult,
  type ReasonCode,
} from "linklint";

import type {
  DecodeEmbeddedWrapperOptions,
  EmbeddedWrapperDecodeResult,
  EmbeddedWrapperDecoded,
  EmbeddedWrapperEnricher,
  EmbeddedWrapperEnricherOptions,
  EmbeddedWrapperFormat,
  EmbeddedWrapperMalformed,
  EmbeddedWrapperOfflineInspection,
  EmbeddedWrapperVendor,
} from "./types.js";

export const EMBEDDED_WRAPPER_SOURCE_ID = "embedded-wrapper.local" as const;
export const EMBEDDED_WRAPPER_SOURCE_VERSION = "1.0.0" as const;
export const EMBEDDED_WRAPPER_CATALOG_VERSION = "2026-07-17" as const;
export const DEFAULT_EMBEDDED_WRAPPER_MAX_DEPTH = 4;
export const MAX_EMBEDDED_WRAPPER_DEPTH = 8;
export const DEFAULT_EMBEDDED_WRAPPER_MAX_URL_LENGTH = 16_384;

const MAX_CONFIGURED_URL_LENGTH = 1_048_576;
const MICROSOFT_SUFFIX = "safelinks.protection.outlook.com";
const PROOFPOINT_HOSTS = new Set(["urldefense.com", "urldefense.proofpoint.com"]);
const PROOFPOINT_V3_RUN_CODES =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const FRESHNESS: EnrichmentFreshness = { status: "fresh", expiresAt: null };

/**
 * Decode one exact, trusted, version-pinned wrapper format without making a
 * network call. Unknown hosts (including ordinary shorteners) are not wrappers.
 */
export function decodeEmbeddedWrapper(
  input: string,
  options: DecodeEmbeddedWrapperOptions = {},
): EmbeddedWrapperDecodeResult {
  const maxUrlLength = boundedUrlLength(options.maxUrlLength);
  const parsed = parseExactUrl(input);
  if (parsed === null) return { status: "not-wrapper", input };

  const vendor = wrapperVendor(parsed.hostname);
  if (vendor === null) return { status: "not-wrapper", input };

  if (input.length > maxUrlLength) {
    return malformed(
      input,
      vendor,
      undefined,
      "decoded-url-too-long",
      "The wrapper URL exceeds the configured local decode bound.",
    );
  }
  if (!isExactHttpsWrapper(parsed)) {
    return unsupported(input, vendor);
  }

  return vendor === "microsoft-safe-links"
    ? decodeMicrosoftSafeLinks(input, parsed, maxUrlLength)
    : decodeProofpoint(input, parsed, maxUrlLength);
}

/**
 * Build the structured local wrapper enricher. Each decoded target is inspected
 * synchronously with core before another nested wrapper is considered.
 */
export function createEmbeddedWrapperEnricher(
  options: EmbeddedWrapperEnricherOptions = {},
): EmbeddedWrapperEnricher {
  const maxDepth = boundedDepth(options.maxDepth);
  const maxUrlLength = boundedUrlLength(options.maxUrlLength);
  const inspectOptions = options.inspectOptions ?? {};
  const now = options.now ?? (() => new Date());

  return {
    id: EMBEDDED_WRAPPER_SOURCE_ID,
    layer: "resolution",
    async enrich(base, context): Promise<EnrichmentReport> {
      const observedAt = observedInstant(now);
      const outcomes: EnrichmentOutcome[] = [];
      let current = base.input;
      let depth = 0;

      while (true) {
        if (context.signal?.aborted === true) {
          outcomes.push(degradationOutcome(
            subjectFor(current),
            observedAt,
            "skipped",
            "caller-aborted",
            false,
          ));
          break;
        }

        if (depth >= maxDepth) {
          const candidate = parseExactUrl(current);
          if (candidate !== null && wrapperVendor(candidate.hostname) !== null) {
            outcomes.push(degradationOutcome(
              subjectFor(current),
              observedAt,
              "failure",
              "wrapper-depth-exceeded",
              false,
              { maxDepth },
            ));
          }
          break;
        }

        const decoded = decodeEmbeddedWrapper(current, { maxUrlLength });
        if (decoded.status === "not-wrapper") {
          if (outcomes.length === 0) {
            outcomes.push(noHitOutcome(inspectionSubject(base), observedAt));
          }
          break;
        }
        if (decoded.status === "unsupported") {
          outcomes.push(degradationOutcome(
            subjectFor(current),
            observedAt,
            "skipped",
            decoded.cause.code,
            false,
            { vendor: decoded.vendor },
          ));
          break;
        }
        if (decoded.status === "malformed") {
          const details: EnrichmentPayload = decoded.format === undefined
            ? { vendor: decoded.vendor }
            : { vendor: decoded.vendor, format: decoded.format };
          outcomes.push(degradationOutcome(
            subjectFor(current),
            observedAt,
            "failure",
            decoded.cause.code,
            false,
            details,
          ));
          break;
        }
        depth += 1;
        const offline = inspect(decoded.destinationUrl, inspectOptions);
        outcomes.push(decodedOutcome(decoded, offline, observedAt, depth));
        current = decoded.destinationUrl;
      }

      return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes };
    },
  };
}

function decodeMicrosoftSafeLinks(
  input: string,
  parsed: URL,
  maxUrlLength: number,
): EmbeddedWrapperDecodeResult {
  const format = "microsoft-safe-links-standard" as const;
  if (parsed.pathname !== "/" || parsed.hash !== "") {
    return unsupported(input, "microsoft-safe-links");
  }

  const destination = exactQueryParameter(parsed.search, "url");
  if (destination === null) {
    return malformed(
      input,
      "microsoft-safe-links",
      format,
      "malformed-wrapper",
      "The Microsoft Safe Links wrapper must contain exactly one valid url parameter.",
    );
  }
  return validateDecoded(
    input,
    destination,
    "microsoft-safe-links",
    format,
    "standard-2026-07",
    maxUrlLength,
  );
}

function decodeProofpoint(
  input: string,
  parsed: URL,
  maxUrlLength: number,
): EmbeddedWrapperDecodeResult {
  if (parsed.hash !== "") return unsupported(input, "proofpoint-url-defense");

  if (parsed.pathname === "/v1/url") {
    const format = "proofpoint-url-defense-v1" as const;
    const encoded = exactRawQueryParameter(parsed.search, "u");
    const destination = encoded === null ? null : decodeProofpointV1Payload(encoded);
    if (destination === null || !hasExactQueryParameter(parsed.search, "k")) {
      return malformedProofpoint(input, format);
    }
    return validateDecoded(
      input,
      destination,
      "proofpoint-url-defense",
      format,
      "v1",
      maxUrlLength,
    );
  }

  if (parsed.pathname === "/v2/url") {
    const format = "proofpoint-url-defense-v2" as const;
    const encoded = exactRawQueryParameter(parsed.search, "u");
    if (
      encoded === null ||
      (!hasExactQueryParameter(parsed.search, "d") &&
        !hasExactQueryParameter(parsed.search, "c"))
    ) {
      return malformedProofpoint(input, format);
    }
    const destination = decodeProofpointV2Payload(encoded);
    if (destination === null) return malformedProofpoint(input, format);
    return validateDecoded(
      input,
      destination,
      "proofpoint-url-defense",
      format,
      "v2",
      maxUrlLength,
    );
  }

  if (parsed.pathname.startsWith("/v3/")) {
    const format = "proofpoint-url-defense-v3" as const;
    const destination = decodeProofpointV3Payload(parsed.pathname + parsed.search);
    if (destination === null) return malformedProofpoint(input, format);
    return validateDecoded(
      input,
      destination,
      "proofpoint-url-defense",
      format,
      "v3.0.1",
      maxUrlLength,
    );
  }

  return unsupported(input, "proofpoint-url-defense");
}

function decodeProofpointV2Payload(value: string): string | null {
  try {
    return decodeProofpointHtmlEntities(
      decodeURIComponent(value.replaceAll("-", "%").replaceAll("_", "/")),
    );
  } catch {
    return null;
  }
}

function decodeProofpointV1Payload(value: string): string | null {
  try {
    return decodeProofpointHtmlEntities(decodeURIComponent(value));
  } catch {
    return null;
  }
}

function decodeProofpointHtmlEntities(value: string): string {
  return value.replace(
    /&(?:amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);/gi,
    (entity): string => {
      const named: Readonly<Record<string, string>> = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
      };
      const normalized = entity.toLowerCase();
      if (normalized in named) return named[normalized]!;
      const hex = normalized.startsWith("&#x");
      const digits = normalized.slice(hex ? 3 : 2, -1);
      const codePoint = Number.parseInt(digits, hex ? 16 : 10);
      return Number.isInteger(codePoint) && codePoint >= 0 && codePoint <= 0x10ffff &&
          !(codePoint >= 0xd800 && codePoint <= 0xdfff)
        ? String.fromCodePoint(codePoint)
        : entity;
    },
  );
}

function decodeProofpointV3Payload(pathAndQuery: string): string | null {
  const match = /^\/v3\/__(.+?)__;([A-Za-z0-9_-]*)!.*\$$/s.exec(pathAndQuery);
  if (match === null) return null;

  try {
    const template = decodeURIComponent(match[1]!);
    const replacements = decodeBase64UrlCharacters(match[2]!);
    if (replacements === null) return null;

    let replacementOffset = 0;
    let output = "";
    for (let index = 0; index < template.length;) {
      if (template[index] !== "*") {
        output += template[index]!;
        index += 1;
        continue;
      }

      let runLength = 1;
      let tokenLength = 1;
      if (template[index + 1] === "*" && index + 2 < template.length) {
        const runCode = template[index + 2]!;
        const runIndex = PROOFPOINT_V3_RUN_CODES.indexOf(runCode);
        if (runIndex < 0) return null;
        runLength = runIndex + 2;
        tokenLength = 3;
      }

      const end = replacementOffset + runLength;
      if (end > replacements.length) return null;
      output += replacements.slice(replacementOffset, end).join("");
      replacementOffset = end;
      index += tokenLength;
    }

    return replacementOffset === replacements.length ? output : null;
  } catch {
    return null;
  }
}

function decodeBase64UrlCharacters(encoded: string): string[] | null {
  if (encoded.length % 4 === 1) return null;
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.toString("base64url") !== encoded) return null;
  try {
    return Array.from(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
}

function validateDecoded(
  input: string,
  destinationUrl: string,
  vendor: EmbeddedWrapperVendor,
  format: EmbeddedWrapperFormat,
  formatVersion: string,
  maxUrlLength: number,
): EmbeddedWrapperDecodeResult {
  if (destinationUrl.length > maxUrlLength) {
    return malformed(
      input,
      vendor,
      format,
      "decoded-url-too-long",
      "The decoded destination exceeds the configured local decode bound.",
    );
  }
  if (destinationUrl.length === 0 || parseExactUrl(destinationUrl) === null) {
    return malformed(
      input,
      vendor,
      format,
      "invalid-decoded-url",
      "The locally decoded destination is not an absolute URL.",
    );
  }
  return { status: "decoded", wrapperUrl: input, destinationUrl, vendor, format, formatVersion };
}

function decodedOutcome(
  decoded: EmbeddedWrapperDecoded,
  offline: InspectResult,
  observedAt: string,
  depth: number,
): EnrichmentOutcome {
  const subject = subjectFor(decoded.destinationUrl);
  const provenance = declaredProvenance(decoded);
  return {
    sourceId: EMBEDDED_WRAPPER_SOURCE_ID,
    layer: "resolution",
    status: "success",
    subject,
    observedAt,
    provenance,
    freshness: FRESHNESS,
    evidence: [
      {
        type: "wrapper.decode",
        subject,
        observedAt,
        provenance,
        freshness: FRESHNESS,
        payload: {
          wrapperUrl: decoded.wrapperUrl,
          destinationUrl: decoded.destinationUrl,
          vendor: decoded.vendor,
          format: decoded.format,
          formatVersion: decoded.formatVersion,
          depth,
          localOnly: true,
          offlineInspection: offlineInspection(offline),
        },
      },
    ],
    findings: offlineFindings(offline),
  };
}

function noHitOutcome(subject: EnrichmentSubject, observedAt: string): EnrichmentOutcome {
  return {
    sourceId: EMBEDDED_WRAPPER_SOURCE_ID,
    layer: "resolution",
    status: "no-hit",
    subject,
    observedAt,
    provenance: declaredProvenance(),
    freshness: FRESHNESS,
    evidence: [],
    findings: [],
  };
}

function degradationOutcome(
  subject: EnrichmentSubject,
  observedAt: string,
  status: "skipped" | "failure",
  code: string,
  retryable: boolean,
  details?: EnrichmentPayload,
): EnrichmentOutcome {
  return {
    sourceId: EMBEDDED_WRAPPER_SOURCE_ID,
    layer: "resolution",
    status,
    subject,
    observedAt,
    provenance: declaredProvenance(),
    freshness: FRESHNESS,
    evidence: [],
    findings: [],
    cause: { code, retryable, ...(details !== undefined ? { details } : {}) },
  };
}

function offlineFindings(result: InspectResult): EnricherFinding[] {
  return result.reasons.flatMap((reason): EnricherFinding[] => {
    if (!Object.hasOwn(REASON_CODES, reason.code)) return [];
    const confusables = reason.code === "confusable_char"
      ? result.confusables.filter((item) => item.component === "host")
      : reason.code === "confusable_in_path"
      ? result.confusables.filter((item) => item.component !== "host")
      : [];
    return [
      {
        code: reason.code as ReasonCode,
        detail: `Decoded wrapper destination: ${reason.detail}`,
        ...(confusables.length > 0 ? { confusables } : {}),
      },
    ];
  });
}

function offlineInspection(result: InspectResult): EmbeddedWrapperOfflineInspection {
  return {
    schemaVersion: result.schemaVersion,
    status: result.status,
    score: result.score,
    severity: result.severity,
    confidence: result.confidence,
    reasonCodes: result.reasons.map((reason) => reason.code),
    checksRun: [...result.checksRun],
    checksSkipped: [...result.checksSkipped],
    dataVersions: { ...result.dataVersions },
    pslSnapshot: { ...result.pslSnapshot },
  };
}

function declaredProvenance(decoded?: EmbeddedWrapperDecoded): EnrichmentProvenance {
  return {
    kind: "declared",
    source: {
      name: "@linklint/online.embedded-wrapper",
      version: EMBEDDED_WRAPPER_SOURCE_VERSION,
    },
    data: decoded === undefined
      ? {
          name: "embedded-wrapper-format-catalog",
          version: EMBEDDED_WRAPPER_CATALOG_VERSION,
        }
      : {
          name: decoded.format,
          version: decoded.formatVersion,
          url: formatDocumentation(decoded.vendor),
        },
  };
}

function formatDocumentation(vendor: EmbeddedWrapperVendor): string {
  return vendor === "microsoft-safe-links"
    ? "https://learn.microsoft.com/defender-office-365/safe-links-about"
    : "https://help.proofpoint.com/Threat_Insight_Dashboard/Concepts/How_do_I_decode_a_rewritten_URL%3F";
}

function exactQueryParameter(search: string, name: string): string | null {
  const raw = exactRawQueryParameter(search, name);
  if (raw === null) return null;
  try {
    return decodeFormComponent(raw);
  } catch {
    return null;
  }
}

function exactRawQueryParameter(search: string, name: string): string | null {
  const matches: string[] = [];
  for (const part of queryParts(search)) {
    const separator = part.indexOf("=");
    const rawName = separator < 0 ? part : part.slice(0, separator);
    let decodedName: string;
    try {
      decodedName = decodeFormComponent(rawName);
    } catch {
      continue;
    }
    if (decodedName === name) {
      matches.push(separator < 0 ? "" : part.slice(separator + 1));
    }
  }
  return matches.length === 1 ? matches[0]! : null;
}

function hasExactQueryParameter(search: string, name: string): boolean {
  let count = 0;
  for (const part of queryParts(search)) {
    const separator = part.indexOf("=");
    const rawName = separator < 0 ? part : part.slice(0, separator);
    try {
      if (decodeFormComponent(rawName) === name) count += 1;
    } catch {
      // Other malformed parameters do not broaden a supported format.
    }
  }
  return count === 1;
}

function queryParts(search: string): string[] {
  return search.startsWith("?") ? search.slice(1).split("&") : [];
}

function decodeFormComponent(value: string): string {
  return decodeURIComponent(value.replaceAll("+", " "));
}

function wrapperVendor(hostname: string): EmbeddedWrapperVendor | null {
  if (isMicrosoftSafeLinksHost(hostname)) return "microsoft-safe-links";
  if (PROOFPOINT_HOSTS.has(hostname)) return "proofpoint-url-defense";
  return null;
}

function isMicrosoftSafeLinksHost(hostname: string): boolean {
  const labels = hostname.split(".");
  if (labels.length !== 5 || labels.slice(1).join(".") !== MICROSOFT_SUFFIX) return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(labels[0]!);
}

function isExactHttpsWrapper(url: URL): boolean {
  return (
    url.protocol === "https:" &&
    url.port === "" &&
    url.username === "" &&
    url.password === ""
  );
}

function parseExactUrl(input: string): URL | null {
  if (input.length === 0 || input !== input.trim()) return null;
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function malformedProofpoint(
  input: string,
  format: EmbeddedWrapperFormat,
): EmbeddedWrapperMalformed {
  return malformed(
    input,
    "proofpoint-url-defense",
    format,
    "malformed-wrapper",
    "The Proofpoint URL Defense payload does not match the pinned local grammar.",
  );
}

function malformed(
  input: string,
  vendor: EmbeddedWrapperVendor,
  format: EmbeddedWrapperFormat | undefined,
  code: EmbeddedWrapperMalformed["cause"]["code"],
  message: string,
): EmbeddedWrapperMalformed {
  return {
    status: "malformed",
    input,
    vendor,
    ...(format !== undefined ? { format } : {}),
    cause: { code, message },
  };
}

function unsupported(
  input: string,
  vendor: EmbeddedWrapperVendor,
): EmbeddedWrapperDecodeResult {
  return {
    status: "unsupported",
    input,
    vendor,
    cause: {
      code: "unsupported-wrapper-format",
      message: "The trusted wrapper host uses a scheme, path, or version outside the pinned catalog.",
    },
  };
}

function inspectionSubject(result: InspectResult): EnrichmentSubject {
  if (result.parsed?.scheme === null && result.parsed.effectiveHost !== null) {
    return { kind: "host", value: result.parsed.effectiveHost };
  }
  return subjectFor(result.input);
}

function subjectFor(value: string): EnrichmentSubject {
  return { kind: "url", value };
}

function boundedDepth(value: number | undefined): number {
  if (value === undefined || !Number.isInteger(value) || value <= 0) {
    return DEFAULT_EMBEDDED_WRAPPER_MAX_DEPTH;
  }
  return Math.min(value, MAX_EMBEDDED_WRAPPER_DEPTH);
}

function boundedUrlLength(value: number | undefined): number {
  if (value === undefined || !Number.isInteger(value) || value <= 0) {
    return DEFAULT_EMBEDDED_WRAPPER_MAX_URL_LENGTH;
  }
  return Math.min(value, MAX_CONFIGURED_URL_LENGTH);
}

function observedInstant(now: () => Date): string {
  const value = now();
  return Number.isFinite(value.getTime()) ? value.toISOString() : new Date(0).toISOString();
}
