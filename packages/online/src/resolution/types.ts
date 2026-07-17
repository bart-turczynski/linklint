import type { Enricher, EnrichmentPayload, InspectOptions, InspectResult } from "linklint";

import type {
  DestinationFetchAuthorization,
  SafeTransport,
  TransportMethod,
} from "../transport/types.js";

/** Exact, locally decodable wrapper grammars shipped by this catalog version. */
export type EmbeddedWrapperFormat =
  | "microsoft-safe-links-standard"
  | "proofpoint-url-defense-v1"
  | "proofpoint-url-defense-v2"
  | "proofpoint-url-defense-v3";

export type EmbeddedWrapperVendor = "microsoft-safe-links" | "proofpoint-url-defense";

export type EmbeddedWrapperDecodeCauseCode =
  | "unsupported-wrapper-format"
  | "malformed-wrapper"
  | "decoded-url-too-long"
  | "invalid-decoded-url";

export interface EmbeddedWrapperDecodeCause {
  readonly code: EmbeddedWrapperDecodeCauseCode;
  readonly message: string;
}

export interface EmbeddedWrapperDecoded {
  readonly status: "decoded";
  readonly wrapperUrl: string;
  readonly destinationUrl: string;
  readonly vendor: EmbeddedWrapperVendor;
  readonly format: EmbeddedWrapperFormat;
  readonly formatVersion: string;
}

export interface EmbeddedWrapperNotMatched {
  readonly status: "not-wrapper";
  readonly input: string;
}

export interface EmbeddedWrapperUnsupported {
  readonly status: "unsupported";
  readonly input: string;
  readonly vendor: EmbeddedWrapperVendor;
  readonly cause: EmbeddedWrapperDecodeCause & {
    readonly code: "unsupported-wrapper-format";
  };
}

export interface EmbeddedWrapperMalformed {
  readonly status: "malformed";
  readonly input: string;
  readonly vendor: EmbeddedWrapperVendor;
  readonly format?: EmbeddedWrapperFormat;
  readonly cause: EmbeddedWrapperDecodeCause & {
    readonly code: Exclude<EmbeddedWrapperDecodeCauseCode, "unsupported-wrapper-format">;
  };
}

/** Total, one-hop local decode result. The decoder never performs network I/O. */
export type EmbeddedWrapperDecodeResult =
  | EmbeddedWrapperDecoded
  | EmbeddedWrapperNotMatched
  | EmbeddedWrapperUnsupported
  | EmbeddedWrapperMalformed;

export interface DecodeEmbeddedWrapperOptions {
  /** Maximum decoded destination length. Invalid values retain the safe default. */
  readonly maxUrlLength?: number;
}

export interface EmbeddedWrapperEnricherOptions extends DecodeEmbeddedWrapperOptions {
  /** Maximum number of nested wrappers to decode. Capped by the implementation hard limit. */
  readonly maxDepth?: number;
  /** Options used when each decoded target is re-inspected through synchronous Layer 1. */
  readonly inspectOptions?: InspectOptions;
  /** Injectable observation clock for deterministic callers and fixtures. */
  readonly now?: () => Date;
}

/** The public factory return is named for discoverability while remaining a core Enricher. */
export type EmbeddedWrapperEnricher = Enricher;

/** Compact evidence projection proving that a decoded target ran through offline Layer 1. */
export interface EmbeddedWrapperOfflineInspection extends EnrichmentPayload {
  readonly schemaVersion: InspectResult["schemaVersion"];
  readonly status: InspectResult["status"];
  readonly score: InspectResult["score"];
  readonly severity: InspectResult["severity"];
  readonly confidence: InspectResult["confidence"];
  readonly reasonCodes: string[];
  readonly checksRun: string[];
  readonly checksSkipped: string[];
  readonly dataVersions: Readonly<Record<string, string>>;
  readonly pslSnapshot: Readonly<Record<string, string | boolean | null>>;
}

/** Declarative or HTTP transition that caused another chain target to be considered. */
export type RedirectChainTransitionKind =
  | "http-redirect"
  | "http-refresh"
  | "html-meta-refresh";

/** Why an exact destination URL is being presented for caller authorization. */
export type RedirectChainAuthorizationReason =
  | "initial"
  | RedirectChainTransitionKind;

export interface RedirectChainAuthorizationRequest {
  readonly url: string;
  readonly hop: number;
  readonly method: TransportMethod;
  readonly reason: RedirectChainAuthorizationReason;
  readonly fromUrl?: string;
}

/**
 * Per-hop consent boundary. Returning `null` refuses the operation; a returned
 * authorization is still checked for an exact URL match by L0.
 */
export type RedirectChainAuthorizer = (
  request: RedirectChainAuthorizationRequest,
) =>
  | DestinationFetchAuthorization
  | null
  | PromiseLike<DestinationFetchAuthorization | null>;

export interface RedirectChainEnricherOptions {
  /** The only transport allowed to connect to an inspected destination. */
  readonly transport: SafeTransport;
  /** Called separately for the initial URL and every discovered target. */
  readonly authorize: RedirectChainAuthorizer;
  /** GET by default. HEAD follows HTTP redirects and Refresh headers but cannot scan HTML. */
  readonly method?: TransportMethod;
  /** L0 allowlisted destination headers only; L0 strips every ambient credential header. */
  readonly headers?: Readonly<Record<string, string>>;
  /** Maximum fetched requests in this chain. Invalid values retain the safe default. */
  readonly maxHops?: number;
  /** Maximum decoded response bytes eligible for declarative-refresh parsing. */
  readonly maxRefreshBytes?: number;
  /** Maximum accepted Refresh/meta-refresh delay. The enricher never sleeps for the delay. */
  readonly maxRefreshDelayMs?: number;
  /** Options used when every chain URL is re-inspected through synchronous Layer 1. */
  readonly inspectOptions?: InspectOptions;
  /** Injectable clock for deterministic pre-transport and stop observations. */
  readonly now?: () => Date;
}

/** The public factory return is named for discoverability while remaining a core Enricher. */
export type RedirectChainEnricher = Enricher;

/** Compact evidence projection proving that a chain URL ran through offline Layer 1. */
export interface RedirectChainOfflineInspection extends EnrichmentPayload {
  readonly schemaVersion: InspectResult["schemaVersion"];
  readonly status: InspectResult["status"];
  readonly score: InspectResult["score"];
  readonly severity: InspectResult["severity"];
  readonly confidence: InspectResult["confidence"];
  readonly reasonCodes: string[];
  readonly checksRun: string[];
  readonly checksSkipped: string[];
  readonly dataVersions: Readonly<Record<string, string>>;
  readonly pslSnapshot: Readonly<Record<string, string | boolean | null>>;
}
