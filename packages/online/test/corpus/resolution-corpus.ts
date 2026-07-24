import type {
  EmbeddedWrapperFormat,
  EmbeddedWrapperVendor,
} from "../../src/resolution/index.js";

/**
 * Labeled Layer 2 resolution corpus (LINK-ddsnssrd / L6b). The single shared
 * fixture consumed by the precision/recall acceptance harness
 * (`resolution-acceptance.test.ts`).
 *
 * Every row belongs to one HEURISTIC family and carries a binary `label`:
 *  - "positive" — the heuristic MUST fire on this input (a genuine wrapper
 *    decode, a real UA-conditioned divergence, a real challenge marker, or an
 *    active MIME sniff mismatch).
 *  - "negative" — the heuristic MUST NOT fire (ordinary/near-miss input,
 *    identical variant responses, ordinary HTML, or a well-formed / nosniff
 *    MIME record).
 *
 * The families deliberately span the classifiers named by the issue:
 *  - `wrapper`     — the pure `decodeEmbeddedWrapper` classifier (no transport).
 *  - `divergence`  — the divergence-probe UA-divergence comparison.
 *  - `challenge`   — the divergence-probe challenge/CAPTCHA marker detection.
 *  - `mime`        — the redirect-chain declared-vs-computed MIME sniff.
 *
 * Transport-backed rows (divergence/challenge/mime) carry only declarative
 * `ResponseStep` fixtures; the acceptance harness drives them exclusively
 * through the deterministic transport fixture harness — never real network.
 * Wrapper rows carry a raw input string decoded purely and locally.
 *
 * Wrapper fixtures are copied verbatim from `embedded-wrapper.test.ts`; the
 * transport fixtures mirror `redirect-chain.test.ts` / `divergence-probe.test.ts`.
 */

/** One scripted transport response, mirroring the per-enricher test harness. */
export interface ResponseStep {
  readonly url: string;
  readonly status: number;
  readonly headers?: Readonly<Record<string, string | readonly string[]>>;
  readonly body?: string;
  readonly method?: "GET" | "HEAD";
}

export type ResolutionFamily = "wrapper" | "divergence" | "challenge" | "mime";
export type ResolutionLabel = "positive" | "negative";

/** Expected exact classification for a wrapper row (guards false decodes). */
export type WrapperExpectation =
  | {
      readonly status: "decoded";
      readonly vendor: EmbeddedWrapperVendor;
      readonly destinationUrl: string;
      readonly format: EmbeddedWrapperFormat;
    }
  | { readonly status: "not-wrapper" }
  | { readonly status: "unsupported"; readonly vendor: EmbeddedWrapperVendor }
  | { readonly status: "malformed"; readonly vendor: EmbeddedWrapperVendor };

export interface WrapperRow {
  readonly family: "wrapper";
  readonly name: string;
  readonly label: ResolutionLabel;
  readonly input: string;
  readonly expected: WrapperExpectation;
}

export interface DivergenceRow {
  readonly family: "divergence";
  readonly name: string;
  readonly label: ResolutionLabel;
  readonly url: string;
  readonly steps: readonly ResponseStep[];
  readonly expected: { readonly divergent: boolean };
}

export interface ChallengeRow {
  readonly family: "challenge";
  readonly name: string;
  readonly label: ResolutionLabel;
  readonly url: string;
  readonly steps: readonly ResponseStep[];
  readonly expected: {
    readonly detected: boolean;
    readonly variant?: string;
    readonly marker?: string;
  };
}

export interface MimeRow {
  readonly family: "mime";
  readonly name: string;
  readonly label: ResolutionLabel;
  readonly url: string;
  readonly step: ResponseStep;
  readonly method?: "GET" | "HEAD";
  readonly expected: { readonly active: boolean; readonly mismatch: boolean };
}

export type ResolutionCorpusRow = WrapperRow | DivergenceRow | ChallengeRow | MimeRow;

// ── Wrapper fixture builders (copied from embedded-wrapper.test.ts) ──────────
const safeLink = (destination: string): string =>
  `https://nam01.safelinks.protection.outlook.com/?url=${encodeURIComponent(destination)}` +
  "&data=05%7C01&reserved=0";

const SAFE_LINK_DESTINATION = "https://example.com/a?x=one+two&y=%25done";
const PROOFPOINT_V2_INPUT =
  "https://urldefense.proofpoint.com/v2/url?" +
  "u=https-3A__media.mnn.com_assets_images_2016_06_jupiter-2Dnasa.jpg.638x0-5Fq80-5Fcrop-2Dsmart.jpg" +
  "&d=DwMBaQ&c=cluster&e=";
const PROOFPOINT_V3_INPUT =
  "https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;" +
  "Kw!-612Flbf0JvQ3kNJkRi5Jg!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$";

const HTML = "text/html; charset=utf-8" as const;

const wrapperRows: readonly WrapperRow[] = [
  // ── Positives: exact, trusted, version-pinned wrappers → decode ───────────
  {
    family: "wrapper",
    name: "microsoft-safe-links-standard",
    label: "positive",
    input: safeLink(SAFE_LINK_DESTINATION),
    expected: {
      status: "decoded",
      vendor: "microsoft-safe-links",
      destinationUrl: SAFE_LINK_DESTINATION,
      format: "microsoft-safe-links-standard",
    },
  },
  {
    family: "wrapper",
    name: "proofpoint-url-defense-v1",
    label: "positive",
    input:
      "https://urldefense.proofpoint.com/v1/url?u=http%3A%2F%2Fwww.bouncycastle.org%2F&k=signature",
    expected: {
      status: "decoded",
      vendor: "proofpoint-url-defense",
      destinationUrl: "http://www.bouncycastle.org/",
      format: "proofpoint-url-defense-v1",
    },
  },
  {
    family: "wrapper",
    name: "proofpoint-url-defense-v2",
    label: "positive",
    input: PROOFPOINT_V2_INPUT,
    expected: {
      status: "decoded",
      vendor: "proofpoint-url-defense",
      destinationUrl:
        "https://media.mnn.com/assets/images/2016/06/jupiter-nasa.jpg.638x0_q80_crop-smart.jpg",
      format: "proofpoint-url-defense-v2",
    },
  },
  {
    family: "wrapper",
    name: "proofpoint-url-defense-v3",
    label: "positive",
    input: PROOFPOINT_V3_INPUT,
    expected: {
      status: "decoded",
      vendor: "proofpoint-url-defense",
      destinationUrl: "https://google.com:443/search?q=a+test&gs=ps",
      format: "proofpoint-url-defense-v3",
    },
  },

  // ── Negatives: ordinary URLs and near-miss look-alikes → NOT a wrapper ────
  {
    family: "wrapper",
    name: "ordinary-url",
    label: "negative",
    input: "https://example.com/path?a=1",
    expected: { status: "not-wrapper" },
  },
  {
    family: "wrapper",
    name: "opaque-shortener",
    label: "negative",
    input: "https://bit.ly/opaque",
    expected: { status: "not-wrapper" },
  },
  {
    family: "wrapper",
    name: "safe-links-suffix-lookalike",
    label: "negative",
    input: "https://nam01.safelinks.protection.outlook.com.evil.test/?url=https://example.com",
    expected: { status: "not-wrapper" },
  },
  {
    family: "wrapper",
    name: "proofpoint-suffix-lookalike",
    label: "negative",
    input: "https://urldefense.proofpoint.com.evil.test/v2/url?u=https-3A__example.com&d=x",
    expected: { status: "not-wrapper" },
  },
  // Trusted host, but a scheme/version outside the pinned catalog → unsupported
  // (NOT a decode: guards against decoding an unverified format).
  {
    family: "wrapper",
    name: "proofpoint-unsupported-version",
    label: "negative",
    input: "https://urldefense.proofpoint.com/v4/url?u=https://example.com",
    expected: { status: "unsupported", vendor: "proofpoint-url-defense" },
  },
  {
    family: "wrapper",
    name: "safe-links-unsupported-scheme",
    label: "negative",
    input: "http://nam01.safelinks.protection.outlook.com/?url=https://example.com",
    expected: { status: "unsupported", vendor: "microsoft-safe-links" },
  },
  // Trusted host + supported format, but payload breaks the pinned grammar →
  // malformed (NOT a decode: guards against emitting a bogus destination).
  {
    family: "wrapper",
    name: "safe-links-duplicate-url-param",
    label: "negative",
    input:
      "https://nam01.safelinks.protection.outlook.com/?url=https://one.example&url=https://two.example",
    expected: { status: "malformed", vendor: "microsoft-safe-links" },
  },
  {
    family: "wrapper",
    name: "proofpoint-v2-malformed-payload",
    label: "negative",
    input: "https://urldefense.proofpoint.com/v2/url?u=https-3X__example.com&d=x",
    expected: { status: "malformed", vendor: "proofpoint-url-defense" },
  },
];

const okHtml = (url: string, body: string): ResponseStep => ({
  url,
  status: 200,
  headers: { "content-type": HTML },
  body,
});

// ── Divergence family (divergence-probe UA-divergence comparison) ───────────
const DIVERGENCE_URL = "https://origin.example/page";

const divergenceRows: readonly DivergenceRow[] = [
  {
    family: "divergence",
    name: "ua-conditioned-cloak",
    label: "positive",
    url: DIVERGENCE_URL,
    steps: [
      okHtml(DIVERGENCE_URL, "<html><body>real</body></html>"),
      {
        url: DIVERGENCE_URL,
        status: 302,
        headers: { location: "https://evil.example/landing" },
      },
    ],
    expected: { divergent: true },
  },
  {
    family: "divergence",
    name: "identical-responses",
    label: "negative",
    url: DIVERGENCE_URL,
    steps: [
      okHtml(DIVERGENCE_URL, "<html><body>hello</body></html>"),
      okHtml(DIVERGENCE_URL, "<html><body>hello</body></html>"),
    ],
    expected: { divergent: false },
  },
];

// ── Challenge family (divergence-probe challenge marker detection) ──────────
const CLOUDFLARE_BODY =
  '<html><head><title>Just a moment...</title>' +
  '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page"></script></head></html>';
const RECAPTCHA_BODY = '<html><body><div class="g-recaptcha" data-sitekey="x"></div></body></html>';
const HCAPTCHA_BODY = '<html><body><div class="h-captcha" data-sitekey="x"></div></body></html>';

const challengeRows: readonly ChallengeRow[] = [
  {
    family: "challenge",
    name: "cloudflare-alt-ua",
    label: "positive",
    url: DIVERGENCE_URL,
    steps: [
      okHtml(DIVERGENCE_URL, "<html><body>real</body></html>"),
      {
        url: DIVERGENCE_URL,
        status: 403,
        headers: { "content-type": HTML },
        body: CLOUDFLARE_BODY,
      },
    ],
    expected: { detected: true, variant: "alt-user-agent", marker: "cloudflare-challenge" },
  },
  {
    family: "challenge",
    name: "recaptcha-baseline",
    label: "positive",
    url: DIVERGENCE_URL,
    steps: [
      okHtml(DIVERGENCE_URL, RECAPTCHA_BODY),
      okHtml(DIVERGENCE_URL, "<html><body>plain</body></html>"),
    ],
    expected: { detected: true, variant: "baseline", marker: "recaptcha" },
  },
  {
    family: "challenge",
    name: "hcaptcha-baseline",
    label: "positive",
    url: DIVERGENCE_URL,
    steps: [
      okHtml(DIVERGENCE_URL, HCAPTCHA_BODY),
      okHtml(DIVERGENCE_URL, "<html><body>plain</body></html>"),
    ],
    expected: { detected: true, variant: "baseline", marker: "hcaptcha" },
  },
  {
    family: "challenge",
    name: "ordinary-html",
    label: "negative",
    url: DIVERGENCE_URL,
    steps: [
      okHtml(DIVERGENCE_URL, "<html><body>hello</body></html>"),
      okHtml(DIVERGENCE_URL, "<html><body>hello</body></html>"),
    ],
    expected: { detected: false },
  },
];

// ── MIME family (redirect-chain declared-vs-computed sniff) ─────────────────
const MIME_URL = "https://origin.example/asset";
const SCRIPT_BODY = "<script>alert(document.cookie)</script>";

const mimeRows: readonly MimeRow[] = [
  {
    family: "mime",
    name: "png-sniffs-to-html-no-nosniff",
    label: "positive",
    url: MIME_URL,
    step: {
      url: MIME_URL,
      status: 200,
      headers: { "content-type": "image/png" },
      body: SCRIPT_BODY,
    },
    expected: { active: true, mismatch: true },
  },
  {
    family: "mime",
    name: "well-formed-html-match",
    label: "negative",
    url: MIME_URL,
    step: {
      url: MIME_URL,
      status: 200,
      headers: { "content-type": HTML },
      body: "<html><body>hello</body></html>",
    },
    expected: { active: false, mismatch: false },
  },
  {
    family: "mime",
    name: "png-html-mismatch-under-nosniff",
    label: "negative",
    url: MIME_URL,
    step: {
      url: MIME_URL,
      status: 200,
      headers: { "content-type": "image/png", "x-content-type-options": "nosniff" },
      body: SCRIPT_BODY,
    },
    expected: { active: false, mismatch: true },
  },
];

export const RESOLUTION_CORPUS: readonly ResolutionCorpusRow[] = [
  ...wrapperRows,
  ...divergenceRows,
  ...challengeRows,
  ...mimeRows,
];
