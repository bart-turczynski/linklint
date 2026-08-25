import {
  ENRICHMENT_SCHEMA_VERSION,
  REASON_CODES,
  inspect,
  openRedirectParamTargets,
  type EnricherFinding,
  type EnrichmentEvidence,
  type EnrichmentFreshness,
  type EnrichmentOutcome,
  type EnrichmentPayload,
  type EnrichmentProvenance,
  type EnrichmentReport,
  type InspectResult,
  type ReasonCode,
} from "linklint";

import type {
  SafeFetchOutcome,
  SafeFetchResponse,
  TransportEvidence,
  TransportMethod,
} from "../transport/types.js";
import type {
  RedirectChainAuthorizationReason,
  RedirectChainEnricher,
  RedirectChainEnricherOptions,
  RedirectChainOfflineInspection,
  RedirectChainTransitionKind,
} from "./types.js";
import { MIME_SNIFF_PREFIX_BYTES, sniffMimeType } from "./mime-sniff.js";

export const REDIRECT_CHAIN_SOURCE_ID = "redirect-chain.http" as const;
export const REDIRECT_CHAIN_SOURCE_VERSION = "1.0.0" as const;
export const DEFAULT_REDIRECT_CHAIN_MAX_HOPS = 10;
export const MAX_REDIRECT_CHAIN_HOPS = 32;
export const DEFAULT_REFRESH_MAX_BYTES = 65_536;
export const DEFAULT_REFRESH_MAX_DELAY_MS = 5_000;

const MAX_REFRESH_BYTES = 1_048_576;
const MAX_REFRESH_DELAY_MS = 60_000;
const MAX_CHAIN_URL_LENGTH = 16_384;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const HTML_MEDIA_TYPES = new Set(["text/html", "application/xhtml+xml"]);
const MAX_ALT_SVC_PROTOCOLS = 16;
const ALT_SVC_PROTOCOL_PATTERN = /^[A-Za-z0-9!#$&^_.+%-]{1,32}$/;
const FRESHNESS: EnrichmentFreshness = { status: "fresh", expiresAt: null };

interface ChainHop {
  readonly url: string;
  readonly hop: number;
  readonly method: TransportMethod;
  readonly observedAt: string;
  readonly response: SafeFetchResponse;
  readonly transportEvidence: TransportEvidence;
  readonly offline: InspectResult;
  readonly transition: FollowTransition | null;
}

interface FollowTransition {
  readonly kind: RedirectChainTransitionKind;
  readonly targetUrl: string;
  readonly delayMs: number | null;
}

/**
 * A confirmed correlation between the lexical `open_redirect_param` suspicion and
 * an observed chain hop that actually landed on the payload's registrable domain
 * (L3, `LINK-rupjqxus`). The finding is informational (weight 0), so it preserves
 * the lexical signal without adding a second probabilistic score.
 */
interface OpenRedirectCorrelation {
  readonly hop: ChainHop;
  readonly finding: EnricherFinding;
  readonly evidence: EnrichmentEvidence;
}

/**
 * Per-hop declared-vs-computed MIME evidence (L5, `LINK-tibzpdft`). Every successfully
 * fetched hop carries a `resolution.mime-evidence` record. The `active` case —
 * a declared/computed essence mismatch that a nosniff-absent consumer would
 * sniff into an executable html/xml type — additionally raises the informational
 * (weight 0) `content_type_mismatch` finding. Hops that cannot be classified
 * (HEAD, empty body) record an explicit incomplete status and emit no finding.
 */
interface MimeEvidence {
  readonly evidence: EnrichmentEvidence;
  readonly finding: EnricherFinding | null;
}

/**
 * A transition that handed the chain from an `https:` hop to an `http:` target
 * (`LINK-emlbzwct`). Raised on the hop that ISSUED the downgrade, once per
 * downgrading transition, so an `https → http → https` bounce reports at the
 * hop where it happened without suppressing the rest of the chain.
 */
interface HttpsDowngrade {
  readonly evidence: EnrichmentEvidence;
  readonly finding: EnricherFinding;
}

type TransitionDecision =
  | { readonly status: "terminal" }
  | { readonly status: "follow"; readonly transition: FollowTransition }
  | {
      readonly status: "stop";
      readonly outcomeStatus: "skipped" | "failure";
      readonly code: string;
      readonly details?: EnrichmentPayload;
      readonly targetUrl?: string;
    };

/**
 * `maxBytes` bounds only the declarative-refresh scan, so exceeding it stops the
 * chain as `skipped`, never `failure` — the hops themselves resolved. No cap can
 * avoid this: measured 2026-07-28, 4 of 10 real landing pages exceed the 64 KiB
 * default and cloudflare.com (1,299,550 bytes) exceeds even `MAX_REFRESH_BYTES`.
 */
interface RefreshPolicy {
  readonly maxBytes: number;
  readonly maxDelayMs: number;
}

/**
 * Build an explicitly authorized L1 redirect/refresh enricher. One L0 session
 * is retained for the whole chain so transport hop, byte, decompression, and
 * time budgets remain cumulative.
 */
export function createRedirectChainEnricher(
  options: RedirectChainEnricherOptions,
): RedirectChainEnricher {
  const method = options.method === "HEAD" ? "HEAD" : "GET";
  const maxHops = boundedInteger(
    options.maxHops,
    DEFAULT_REDIRECT_CHAIN_MAX_HOPS,
    MAX_REDIRECT_CHAIN_HOPS,
  );
  const refreshPolicy: RefreshPolicy = {
    maxBytes: boundedInteger(
      options.maxRefreshBytes,
      DEFAULT_REFRESH_MAX_BYTES,
      MAX_REFRESH_BYTES,
    ),
    maxDelayMs: boundedNumber(
      options.maxRefreshDelayMs,
      DEFAULT_REFRESH_MAX_DELAY_MS,
      MAX_REFRESH_DELAY_MS,
    ),
  };
  const inspectOptions = options.inspectOptions ?? {};
  const now = options.now ?? (() => new Date());

  return {
    id: REDIRECT_CHAIN_SOURCE_ID,
    layer: "resolution",
    async enrich(base, context): Promise<EnrichmentReport> {
      const initial = canonicalHttpUrl(base.input);
      if (initial === null) {
        return report([
          degradationOutcome(
            base.input,
            observedInstant(now),
            "failure",
            "invalid-target",
            false,
          ),
        ]);
      }

      const session = options.transport.createSession();
      const hops: ChainHop[] = [];
      const stops: EnrichmentOutcome[] = [];
      const seen = new Set<string>();
      let currentUrl = initial;
      let currentOffline = inspect(currentUrl, inspectOptions);
      let reason: RedirectChainAuthorizationReason = "initial";
      let fromUrl: string | undefined;

      while (true) {
        if (context.signal?.aborted === true) {
          stops.push(degradationOutcome(
            currentUrl,
            observedInstant(now),
            "skipped",
            "caller-aborted",
            false,
            undefined,
            currentOffline,
          ));
          break;
        }
        if (seen.has(currentUrl)) {
          stops.push(degradationOutcome(
            currentUrl,
            observedInstant(now),
            "failure",
            "redirect-loop",
            false,
            { url: currentUrl },
            currentOffline,
          ));
          break;
        }
        if (hops.length >= maxHops) {
          stops.push(degradationOutcome(
            currentUrl,
            observedInstant(now),
            "failure",
            "hop-limit",
            false,
            { maxHops },
            currentOffline,
          ));
          break;
        }

        const hop = hops.length + 1;
        let authorization;
        try {
          authorization = await options.authorize({
            url: currentUrl,
            hop,
            method,
            reason,
            ...(fromUrl === undefined ? {} : { fromUrl }),
          });
        } catch {
          stops.push(degradationOutcome(
            currentUrl,
            observedInstant(now),
            "failure",
            "authorization-error",
            false,
            undefined,
            currentOffline,
          ));
          break;
        }
        if (authorization === null) {
          stops.push(degradationOutcome(
            currentUrl,
            observedInstant(now),
            "skipped",
            "authorization-denied",
            false,
            { hop },
            currentOffline,
          ));
          break;
        }

        seen.add(currentUrl);
        const fetched = await session.fetch({
          url: currentUrl,
          authorization,
          method,
          ...(options.headers === undefined ? {} : { headers: options.headers }),
          ...(context.signal === undefined ? {} : { signal: context.signal }),
        });
        if (fetched.status !== "success") {
          stops.push(transportDegradation(fetched, currentOffline));
          break;
        }

        const decision = transitionFor(fetched.response, currentUrl, method, refreshPolicy);
        const transition = decision.status === "follow" ? decision.transition : null;
        hops.push({
          url: currentUrl,
          hop,
          method,
          observedAt: fetched.observedAt,
          response: fetched.response,
          transportEvidence: fetched.evidence,
          offline: currentOffline,
          transition,
        });

        if (decision.status === "terminal") break;
        if (decision.status === "stop") {
          const stoppedSubject = decision.targetUrl ?? currentUrl;
          const stoppedOffline = decision.targetUrl === undefined
            ? currentOffline
            : inspect(decision.targetUrl, inspectOptions);
          stops.push(degradationOutcome(
            stoppedSubject,
            observedInstant(now),
            decision.outcomeStatus,
            decision.code,
            false,
            decision.details,
            stoppedOffline,
          ));
          break;
        }

        const targetOffline = inspect(decision.transition.targetUrl, inspectOptions);
        fromUrl = currentUrl;
        currentUrl = decision.transition.targetUrl;
        currentOffline = targetOffline;
        reason = decision.transition.kind;
      }

      const worst = worstHop(hops);
      const baseCodes = new Set(
        base.reasons.filter((item) => item.suppressed !== true).map((item) => item.code),
      );
      const correlation = correlateOpenRedirect(
        base,
        hops,
        baseCodes,
        inspectOptions.maxDecodeDepth,
      );
      const outcomes = hops.map((hop) => hopOutcome(
        hop,
        hop === worst ? offlineFindings(hop.offline, hop.hop, baseCodes) : [],
        correlation !== null && correlation.hop === hop ? correlation : null,
        mimeEvidenceFor(hop),
        httpsDowngradeFor(hop),
        altSvcEvidenceFor(hop),
      ));
      outcomes.push(...stops);
      return report(outcomes);
    },
  };
}

function transitionFor(
  response: SafeFetchResponse,
  currentUrl: string,
  method: TransportMethod,
  policy: RefreshPolicy,
): TransitionDecision {
  if (REDIRECT_STATUSES.has(response.status)) {
    const location = singleHeader(response.headers, "location");
    if (location.status !== "value") {
      return stop("failure", "invalid-target", {
        mechanism: "http-redirect",
        reason: location.status === "missing" ? "missing-location" : "ambiguous-location",
      });
    }
    return resolveTransition("http-redirect", location.value, currentUrl, null);
  }

  const refresh = singleHeader(response.headers, "refresh");
  const contentType = parseContentType(singleHeaderValue(response.headers, "content-type"));
  if (refresh.status === "ambiguous") {
    return stop("failure", "invalid-refresh", { reason: "ambiguous-header" });
  }
  if (refresh.status === "value") {
    const eligibility = refreshEligibility(response.body, contentType, policy);
    if (eligibility !== null) return eligibility;
    return parseRefreshTransition("http-refresh", refresh.value, currentUrl, policy.maxDelayMs);
  }

  if (method === "HEAD" || contentType === null || !HTML_MEDIA_TYPES.has(contentType.mediaType)) {
    return { status: "terminal" };
  }
  if (response.body.byteLength > policy.maxBytes) {
    return stop("skipped", "refresh-body-too-large", {
      maxRefreshBytes: policy.maxBytes,
      observedBytes: response.body.byteLength,
    });
  }
  const decoded = decodeHtml(response.body, contentType.charset);
  if (decoded.status === "unsupported") {
    return stop("failure", "refresh-charset-unsupported", { charset: decoded.charset });
  }
  const metaContent = firstMetaRefreshContent(decoded.text);
  if (metaContent === null) return { status: "terminal" };
  return parseRefreshTransition(
    "html-meta-refresh",
    metaContent,
    currentUrl,
    policy.maxDelayMs,
  );
}

function refreshEligibility(
  body: Uint8Array,
  contentType: ContentType | null,
  policy: RefreshPolicy,
): TransitionDecision | null {
  if (body.byteLength > policy.maxBytes) {
    return stop("skipped", "refresh-body-too-large", {
      maxRefreshBytes: policy.maxBytes,
      observedBytes: body.byteLength,
    });
  }
  if (contentType === null || !HTML_MEDIA_TYPES.has(contentType.mediaType)) {
    return stop("skipped", "refresh-mime-unsupported", {
      mediaType: contentType?.mediaType ?? null,
    });
  }
  const decoded = decodeHtml(body, contentType.charset);
  return decoded.status === "unsupported"
    ? stop("failure", "refresh-charset-unsupported", { charset: decoded.charset })
    : null;
}

function parseRefreshTransition(
  kind: Exclude<RedirectChainTransitionKind, "http-redirect">,
  value: string,
  currentUrl: string,
  maxDelayMs: number,
): TransitionDecision {
  const match = /^\s*(\d+(?:\.\d+)?)\s*(?:;\s*url\s*=\s*(.*?)\s*)?$/is.exec(value);
  if (match === null) return stop("failure", "invalid-refresh", { mechanism: kind });
  const delayMs = Number(match[1]) * 1_000;
  if (!Number.isFinite(delayMs)) {
    return stop("failure", "invalid-refresh", { mechanism: kind });
  }
  if (delayMs > maxDelayMs) {
    return stop("skipped", "refresh-delay-exceeded", {
      mechanism: kind,
      delayMs,
      maxRefreshDelayMs: maxDelayMs,
    });
  }
  const rawTarget = unquoteRefreshTarget(match[2] ?? "");
  const target = rawTarget === "" ? currentUrl : rawTarget;
  return resolveTransition(kind, target, currentUrl, delayMs);
}

function resolveTransition(
  kind: RedirectChainTransitionKind,
  rawTarget: string,
  currentUrl: string,
  delayMs: number | null,
): TransitionDecision {
  let target: URL;
  try {
    target = new URL(rawTarget.trim(), currentUrl);
  } catch {
    return stop("failure", "invalid-target", { mechanism: kind });
  }
  target.hash = "";
  if (
    (target.protocol !== "http:" && target.protocol !== "https:") ||
    target.href.length > MAX_CHAIN_URL_LENGTH
  ) {
    return stop(
      "failure",
      "invalid-target",
      { mechanism: kind, scheme: target.protocol },
      target.href,
    );
  }
  return {
    status: "follow",
    transition: { kind, targetUrl: target.href, delayMs },
  };
}

function hopOutcome(
  hop: ChainHop,
  findings: EnricherFinding[],
  correlation: OpenRedirectCorrelation | null,
  mime: MimeEvidence,
  downgrade: HttpsDowngrade | null,
  altSvc: EnrichmentEvidence | null,
): EnrichmentOutcome {
  const subject = { kind: "url" as const, value: hop.url };
  const provenance = declaredProvenance();
  return {
    sourceId: REDIRECT_CHAIN_SOURCE_ID,
    layer: "resolution",
    status: "success",
    subject,
    observedAt: hop.observedAt,
    provenance,
    freshness: FRESHNESS,
    evidence: [
      {
        type: "resolution.chain-hop",
        subject,
        observedAt: hop.observedAt,
        provenance,
        freshness: FRESHNESS,
        payload: {
          hop: hop.hop,
          requestUrl: hop.url,
          method: hop.method,
          responseStatus: hop.response.status,
          encodedBytes: hop.response.encodedBytes,
          decompressedBytes: hop.response.decompressedBytes,
          transport: transportPayload(hop.transportEvidence),
          transition: hop.transition === null
            ? null
            : {
                kind: hop.transition.kind,
                targetUrl: hop.transition.targetUrl,
                delayMs: hop.transition.delayMs,
              },
          offlineInspection: offlineInspection(hop.offline),
        },
      },
      ...(correlation === null ? [] : [correlation.evidence]),
      mime.evidence,
      ...(downgrade === null ? [] : [downgrade.evidence]),
      ...(altSvc === null ? [] : [altSvc]),
    ],
    findings: [
      ...findings,
      ...(correlation === null ? [] : [correlation.finding]),
      ...(mime.finding === null ? [] : [mime.finding]),
      ...(downgrade === null ? [] : [downgrade.finding]),
    ],
  };
}

/**
 * Name an `https:` → `http:` transition, which is derivable from the shipped
 * `resolution.chain-hop` payloads but was never stated (`LINK-emlbzwct`).
 *
 * The discriminator is the TRANSITION, never a single hop's scheme: an
 * `http://` input at hop 1 is an ordinary plaintext origin that
 * `canonicalHttpUrl` accepts, so it is not a downgrade, and neither is an
 * upgrade or an `https:` → `https:` hop. All three transition kinds
 * (`http-redirect`, `http-refresh`, `html-meta-refresh`) are covered, because
 * every one of them arrives here as the same `FollowTransition`.
 *
 * Keyed on the transition rather than on the target hop's fetch, so a chain cut
 * short after the downgrade — hop cap, denied authorization, transport failure
 * — still reports the plaintext target it was directed to. The fetched
 * redirect/refresh response proves that on its own.
 *
 * The chain is never stopped and there is no option to stop it. Refusal buys no
 * confidentiality — L0 sends no body, no cookie jar, no credentials, and strips
 * the caller's `Referer` — while costing detection, since a refused hop is never
 * fetched and `worstHop`, `correlateOpenRedirect` and `mimeEvidenceFor` all read
 * fetched hops only. Informational (weight 0): a downgrade is a fact worth
 * reporting, not a claim that the URL is deceptive.
 */
function httpsDowngradeFor(hop: ChainHop): HttpsDowngrade | null {
  const transition = hop.transition;
  if (transition === null) return null;
  const fromScheme = schemeOf(hop.url);
  const toScheme = schemeOf(transition.targetUrl);
  if (fromScheme !== "https:" || toScheme !== "http:") return null;

  const subject = { kind: "url" as const, value: hop.url };
  const provenance = declaredProvenance();
  const payload: EnrichmentPayload = {
    hop: hop.hop,
    targetHop: hop.hop + 1,
    transitionKind: transition.kind,
    fromUrl: hop.url,
    fromScheme,
    toUrl: transition.targetUrl,
    toScheme,
    transportProtocol: hop.transportEvidence.protocol ?? null,
  };
  return {
    finding: {
      code: "https_downgrade_observed",
      detail:
        `Hop ${hop.hop} was fetched over https and its ${transition.kind} sent the chain to the ` +
        `plaintext target '${transition.targetUrl}' — the chain left TLS. Observed and reported, ` +
        `never refused: refusing buys no confidentiality (no body, cookies, or credentials are ` +
        `sent and the caller's Referer is stripped) while costing observation of the remaining ` +
        `hops. Informational (weight 0) — a downgrade is not itself deceptive`,
    },
    evidence: {
      type: "resolution.https-downgrade",
      subject,
      observedAt: hop.observedAt,
      provenance,
      freshness: FRESHNESS,
      payload,
    },
  };
}

function schemeOf(url: string): string | null {
  try {
    return new URL(url).protocol;
  } catch {
    return null;
  }
}

/**
 * Record an `Alt-Svc` advertisement the hop's response carried (`LINK-zmkkoeyl`).
 *
 * A browser that reads `Alt-Svc: h3=":443"` may move its next request onto the
 * named alternative authority. This stack cannot: L0 pins ALPN to `http/1.1`,
 * keeps no alternative-service cache, and `transitionFor` branches only on the
 * redirect statuses, a `Refresh` header, and an in-body meta refresh. So the
 * advertisement names a place a browser could have gone and linklint did not,
 * and that gap between the two is what makes it worth recording.
 *
 * Evidence only: no finding, no reason code, weight 0, byte-neutral on the
 * verdict. An advertisement is a routing hint, not a statement about whether
 * the URL is deceptive. It also costs nothing to read — L0 already holds the
 * header, so there is no extra request and no extra disclosure.
 *
 * `Alt-Svc` is a list header, so every field line is kept verbatim and the
 * protocol ids are parsed out of all of them under a bounded, deduplicated cap.
 * The special `clear` value is recorded as itself: it withdraws advertisements
 * rather than making one.
 */
function altSvcEvidenceFor(hop: ChainHop): EnrichmentEvidence | null {
  const advertisements = headerValues(hop.response.headers, "alt-svc");
  if (advertisements.length === 0) return null;

  const protocols: string[] = [];
  let cleared = false;
  for (const advertisement of advertisements) {
    for (const entry of advertisement.split(",")) {
      const token = (entry.split("=")[0] ?? "").trim();
      if (token.toLowerCase() === "clear") {
        cleared = true;
        continue;
      }
      if (!ALT_SVC_PROTOCOL_PATTERN.test(token)) continue;
      if (protocols.includes(token)) continue;
      if (protocols.length >= MAX_ALT_SVC_PROTOCOLS) continue;
      protocols.push(token);
    }
  }

  return {
    type: "resolution.alt-svc",
    subject: { kind: "url", value: hop.url },
    observedAt: hop.observedAt,
    provenance: declaredProvenance(),
    freshness: FRESHNESS,
    payload: {
      hop: hop.hop,
      advertisements: [...advertisements],
      protocols,
      cleared,
      followed: false,
      requestProtocol: "http/1.1",
    },
  };
}

/** Every field line sent under `name`, trimmed, with empties dropped. */
function headerValues(
  headers: Readonly<Record<string, readonly string[]>>,
  name: string,
): readonly string[] {
  return Object.entries(headers)
    .filter(([headerName]) => headerName.toLowerCase() === name)
    .flatMap(([, values]) => values.map((value) => value.trim()))
    .filter((value) => value !== "");
}

/**
 * Build the per-hop declared-vs-computed MIME evidence record, and — only for
 * the active script-injection-via-sniffing case — an informational finding.
 *
 * A hop that cannot be classified (HEAD request, or an empty body with nothing
 * to sniff) records an explicit `incomplete` status and emits no finding.
 * Otherwise the byte prefix is sniffed independently of the declared essence:
 * a mismatch is recorded, and marked `active` when a nosniff-absent consumer
 * would sniff an executable html/xml type from a resource declared as something
 * non-executable. `active` is the only case that carries a finding.
 */
function mimeEvidenceFor(hop: ChainHop): MimeEvidence {
  const subject = { kind: "url" as const, value: hop.url };
  const provenance = declaredProvenance();
  const declared = singleHeaderValue(hop.response.headers, "content-type");
  const noSniff =
    (singleHeaderValue(hop.response.headers, "x-content-type-options") ?? "")
      .trim()
      .toLowerCase() === "nosniff";
  const body = hop.response.body;

  if (hop.method === "HEAD" || body.byteLength === 0) {
    return {
      finding: null,
      evidence: {
        type: "resolution.mime-evidence",
        subject,
        observedAt: hop.observedAt,
        provenance,
        freshness: FRESHNESS,
        payload: {
          hop: hop.hop,
          declaredEssence: declared,
          noSniff,
          status: "incomplete",
          cause: "no-body",
        },
      },
    };
  }

  const sniff = sniffMimeType(body, declared);
  const mismatch =
    sniff.declaredEssence !== null && sniff.declaredEssence !== sniff.computedEssence;
  const active =
    mismatch &&
    !noSniff &&
    (sniff.computedEssence === "text/html" || sniff.computedEssence === "text/xml") &&
    sniff.declaredEssence !== "text/html" &&
    sniff.declaredEssence !== "text/xml";

  return {
    finding: active
      ? {
          code: "content_type_mismatch",
          detail:
            `Hop ${hop.hop} response declared '${sniff.declaredEssence}' but its bytes sniff to ` +
            `'${sniff.computedEssence}' with no nosniff — a content-type mismatch a sniffing ` +
            `consumer could execute; informational corroboration, not proof of exploitation.`,
        }
      : null,
    evidence: {
      type: "resolution.mime-evidence",
      subject,
      observedAt: hop.observedAt,
      provenance,
      freshness: FRESHNESS,
      payload: {
        hop: hop.hop,
        declaredEssence: sniff.declaredEssence,
        computedEssence: sniff.computedEssence,
        rule: sniff.rule,
        noSniff,
        sniffedBytes: Math.min(body.byteLength, MIME_SNIFF_PREFIX_BYTES),
        status: "classified",
        mismatch,
        active,
      },
    },
  };
}

function transportDegradation(
  outcome: Exclude<SafeFetchOutcome, { status: "success" }>,
  offline: InspectResult,
): EnrichmentOutcome {
  return degradationOutcome(
    outcome.subject.value,
    outcome.observedAt,
    outcome.status === "blocked" ? "skipped" : "failure",
    outcome.cause.code,
    retryableTransportCause(outcome.cause.code),
    outcome.cause.details,
    offline,
    [{
      type: "transport.attempt",
      subject: outcome.subject,
      observedAt: outcome.observedAt,
      provenance: declaredProvenance(),
      freshness: FRESHNESS,
      payload: transportPayload(outcome.evidence),
    }],
  );
}

function degradationOutcome(
  url: string,
  observedAt: string,
  status: "skipped" | "failure",
  code: string,
  retryable: boolean,
  details?: EnrichmentPayload,
  offline?: InspectResult,
  suppliedEvidence: EnrichmentEvidence[] = [],
): EnrichmentOutcome {
  const subject = { kind: "url" as const, value: url };
  const provenance = declaredProvenance();
  const evidence = [...suppliedEvidence];
  if (offline !== undefined) {
    evidence.push({
      type: "resolution.target-inspection",
      subject,
      observedAt,
      provenance,
      freshness: FRESHNESS,
      payload: { offlineInspection: offlineInspection(offline) },
    });
  }
  return {
    sourceId: REDIRECT_CHAIN_SOURCE_ID,
    layer: "resolution",
    status,
    subject,
    observedAt,
    provenance,
    freshness: FRESHNESS,
    evidence,
    findings: [],
    cause: { code, retryable, ...(details === undefined ? {} : { details }) },
  };
}

function worstHop(hops: readonly ChainHop[]): ChainHop | undefined {
  let worst: ChainHop | undefined;
  for (const hop of hops) {
    if (worst === undefined || (hop.offline.score ?? -1) > (worst.offline.score ?? -1)) {
      worst = hop;
    }
  }
  return worst;
}

/**
 * Correlate a lexical `open_redirect_param` suspicion with the observed chain.
 *
 * Only fires when the base offline result actually raised `open_redirect_param`
 * AND a resolved hop was observed to leave the input's registrable domain and
 * land on a registrable domain named by a decoded redirect-parameter payload —
 * the same registrable-domain-divergence premise the lexical detector uses, not
 * a full-origin comparison. Incomplete resolution that never reaches a payload
 * domain returns `null` (inconclusive: nothing is emitted). The result is an
 * informational, weight-0 corroboration, never a duplicate probabilistic score.
 */
function correlateOpenRedirect(
  base: InspectResult,
  hops: readonly ChainHop[],
  baseCodes: ReadonlySet<string>,
  maxDecodeDepth: number | undefined,
): OpenRedirectCorrelation | null {
  if (!baseCodes.has("open_redirect_param")) return null;

  const inputDomainLower = base.parsed?.registrableDomain?.toLowerCase() ?? null;
  const targets = openRedirectParamTargets(
    base.parsed?.query ?? null,
    inputDomainLower,
    maxDecodeDepth,
  );
  if (targets.length === 0) return null;

  // First matched payload wins per landing domain; mirrors the lexical detector's
  // left-to-right precedence when multiple redirect parameters are present.
  const paramByDomain = new Map<string, string>();
  for (const target of targets) {
    const key = target.registrableDomain.toLowerCase();
    if (!paramByDomain.has(key)) paramByDomain.set(key, target.param);
  }

  for (const hop of hops) {
    const observed = hop.offline.parsed?.registrableDomain ?? null;
    if (observed === null) continue;
    const observedLower = observed.toLowerCase();
    // An on-site hop is not an off-site landing. Payload domains already exclude
    // the input domain, so this only guards a null/blank input domain.
    if (observedLower === inputDomainLower) continue;
    const param = paramByDomain.get(observedLower);
    if (param === undefined) continue;

    const subject = { kind: "url" as const, value: hop.url };
    const provenance = declaredProvenance();
    const payload: EnrichmentPayload = {
      param,
      payloadRegistrableDomain: observed,
      observedRegistrableDomain: observed,
      inputRegistrableDomain: base.parsed?.registrableDomain ?? null,
      hop: hop.hop,
      consistent: true,
    };
    return {
      hop,
      finding: {
        code: "open_redirect_observed",
        detail:
          `Observed redirect chain left '${base.parsed?.registrableDomain ?? "(none)"}' and landed ` +
          `on '${observed}' at hop ${hop.hop}, matching the open_redirect_param payload in ` +
          `parameter '${param}' — resolution-time corroboration of the lexical suspicion, not ` +
          `proof of general exploitability`,
      },
      evidence: {
        type: "resolution.open-redirect-observed",
        subject,
        observedAt: hop.observedAt,
        provenance,
        freshness: FRESHNESS,
        payload,
      },
    };
  }

  return null;
}

function offlineFindings(
  result: InspectResult,
  hop: number,
  excludedCodes: ReadonlySet<string>,
): EnricherFinding[] {
  const emitted = new Set<string>();
  return result.reasons.flatMap((reason): EnricherFinding[] => {
    if (
      !Object.hasOwn(REASON_CODES, reason.code) ||
      excludedCodes.has(reason.code) ||
      emitted.has(reason.code)
    ) return [];
    emitted.add(reason.code);
    const confusables = reason.code === "confusable_char"
      ? result.confusables.filter((item) => item.component === "host")
      : reason.code === "confusable_in_path"
      ? result.confusables.filter((item) => item.component !== "host")
      : [];
    return [{
      code: reason.code as ReasonCode,
      detail: `Resolved chain hop ${hop}: ${reason.detail}`,
      ...(confusables.length === 0 ? {} : { confusables }),
    }];
  });
}

function offlineInspection(result: InspectResult): RedirectChainOfflineInspection {
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

function transportPayload(evidence: TransportEvidence): EnrichmentPayload {
  return {
    hop: evidence.hop,
    ...(evidence.protocol === undefined ? {} : { protocol: evidence.protocol }),
    ...(evidence.hostname === undefined ? {} : { hostname: evidence.hostname }),
    ...(evidence.port === undefined ? {} : { port: evidence.port }),
    ...(evidence.resolvedAddresses === undefined
      ? {}
      : { resolvedAddresses: [...evidence.resolvedAddresses] }),
    ...(evidence.selectedAddress === undefined
      ? {}
      : { selectedAddress: evidence.selectedAddress }),
  };
}

function declaredProvenance(): EnrichmentProvenance {
  return {
    kind: "declared",
    source: {
      name: "@linklint/online.redirect-chain",
      version: REDIRECT_CHAIN_SOURCE_VERSION,
    },
    data: null,
  };
}

interface ContentType {
  readonly mediaType: string;
  readonly charset: string | null;
}

function parseContentType(value: string | null): ContentType | null {
  if (value === null) return null;
  const [rawMediaType, ...parameters] = value.split(";");
  const mediaType = rawMediaType?.trim().toLowerCase() ?? "";
  if (mediaType === "") return null;
  let charset: string | null = null;
  for (const parameter of parameters) {
    const match = /^\s*charset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;]+))\s*$/i.exec(parameter);
    if (match !== null) charset = (match[1] ?? match[2] ?? match[3] ?? "").toLowerCase();
  }
  return { mediaType, charset };
}

type DecodedHtml =
  | { readonly status: "decoded"; readonly text: string }
  | { readonly status: "unsupported"; readonly charset: string };

function decodeHtml(body: Uint8Array, declaredCharset: string | null): DecodedHtml {
  const charset = (declaredCharset ?? "utf-8").toLowerCase();
  const encoding = charset === "utf-8" || charset === "utf8" || charset === "us-ascii"
    ? "utf-8"
    : charset === "iso-8859-1" || charset === "latin1" || charset === "windows-1252"
    ? "windows-1252"
    : null;
  if (encoding === null) return { status: "unsupported", charset };
  return { status: "decoded", text: new TextDecoder(encoding).decode(body) };
}

function firstMetaRefreshContent(html: string): string | null {
  const visibleMarkup = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style|textarea|title)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "");
  const tags = visibleMarkup.match(/<meta\b[^>]*>/gi) ?? [];
  for (const tag of tags) {
    const attributes = htmlAttributes(tag);
    if (attributes.get("http-equiv")?.toLowerCase() === "refresh") {
      return attributes.get("content") ?? "";
    }
  }
  return null;
}

function htmlAttributes(tag: string): Map<string, string> {
  const attributes = new Map<string, string>();
  const body = tag.replace(/^<meta\b/i, "").replace(/>$/, "");
  const pattern = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const match of body.matchAll(pattern)) {
    const name = match[1]?.toLowerCase();
    if (name !== undefined && !attributes.has(name)) {
      attributes.set(name, decodeHtmlEntities(match[2] ?? match[3] ?? match[4] ?? ""));
    }
  }
  return attributes;
}

function decodeHtmlEntities(value: string): string {
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
      const point = Number.parseInt(digits, hex ? 16 : 10);
      return Number.isInteger(point) && point >= 0 && point <= 0x10ffff &&
          !(point >= 0xd800 && point <= 0xdfff)
        ? String.fromCodePoint(point)
        : entity;
    },
  );
}

function unquoteRefreshTarget(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    if ((first === '"' || first === "'") && trimmed.at(-1) === first) {
      return trimmed.slice(1, -1).trim();
    }
  }
  return trimmed;
}

type SingleHeader =
  | { readonly status: "missing" }
  | { readonly status: "ambiguous" }
  | { readonly status: "value"; readonly value: string };

function singleHeader(
  headers: Readonly<Record<string, readonly string[]>>,
  name: string,
): SingleHeader {
  const values = Object.entries(headers)
    .filter(([headerName]) => headerName.toLowerCase() === name)
    .flatMap(([, headerValues]) => [...headerValues]);
  if (values.length === 0) return { status: "missing" };
  if (values.length !== 1 || values[0]?.trim() === "") return { status: "ambiguous" };
  return { status: "value", value: values[0]!.trim() };
}

function singleHeaderValue(
  headers: Readonly<Record<string, readonly string[]>>,
  name: string,
): string | null {
  const header = singleHeader(headers, name);
  return header.status === "value" ? header.value : null;
}

function canonicalHttpUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.href.length > MAX_CHAIN_URL_LENGTH) return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function stop(
  outcomeStatus: "skipped" | "failure",
  code: string,
  details?: EnrichmentPayload,
  targetUrl?: string,
): TransitionDecision {
  return {
    status: "stop",
    outcomeStatus,
    code,
    ...(details === undefined ? {} : { details }),
    ...(targetUrl === undefined ? {} : { targetUrl }),
  };
}

function retryableTransportCause(code: string): boolean {
  return code === "dns-timeout" || code === "dns-error" || code === "connect-refused" ||
    code === "connect-timeout" || code === "connect-error" || code === "tls-handshake" ||
    code === "http-reset" || code === "http-timeout" || code === "http-error" ||
    code === "timeout";
}

function boundedInteger(value: number | undefined, fallback: number, maximum: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? Math.min(value, maximum)
    : fallback;
}

function boundedNumber(value: number | undefined, fallback: number, maximum: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.min(value, maximum)
    : fallback;
}

function observedInstant(now: () => Date): string {
  try {
    const date = now();
    return Number.isFinite(date.getTime()) ? date.toISOString() : new Date(0).toISOString();
  } catch {
    return new Date(0).toISOString();
  }
}

function report(outcomes: EnrichmentOutcome[]): EnrichmentReport {
  return { schemaVersion: ENRICHMENT_SCHEMA_VERSION, outcomes };
}
