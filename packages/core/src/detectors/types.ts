import type { Confusable, Layer, ParsedUrl } from "../schema/types.js";
import type { ReasonCode } from "../schema/reason-codes.js";

/**
 * Everything a detector needs about a parsed input. Built once by the pipeline
 * and passed to every detector. Carries both the visual/normalized values
 * (`host`, `hostLabels`, …) and the raw, as-written values (`rawHost`, `path`,
 * …) so character-level detectors can see exactly what was in the input.
 */
export interface InspectionContext {
  /** Original, untrimmed input. */
  input: string;
  scheme: string | null;
  userinfo: string | null;
  /** Host as written, may contain invisible/bidi characters. No brackets. */
  rawHost: string;
  /** Visual host: `rawHost` with invisible/format characters removed. */
  host: string;
  /** Unicode (U-label) form of `host`: `xn--` labels decoded. For confusable/
   *  script analysis, which must see through punycode. */
  hostUnicode: string;
  isIp: boolean;
  /** Visual host split into labels (left-to-right). */
  hostLabels: string[];
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  port: number | null;
  /** Raw path (may be empty string). */
  path: string;
  /** Raw query without leading `?`, or null. */
  query: string | null;
  /** Raw fragment without leading `#`, or null. */
  fragment: string | null;
  /** The serialized parsed view (what appears on the result). */
  parsed: ParsedUrl;
}

/**
 * A detector's output. The core attaches the weight (from the registry) and
 * builds the final `Reason`; detectors supply only the code + human detail and,
 * for confusable detectors, the per-character expansion.
 */
export interface DetectorFinding {
  code: ReasonCode;
  detail: string;
  /** Per-character confusable entries that bubble up to top-level `confusables[]`. */
  confusables?: Confusable[];
}

/** A lexical detector. v1 detectors all use `layer: "lexical"`. */
export interface Detector {
  id: string;
  layer: Layer;
  run(ctx: InspectionContext): DetectorFinding[];
}
