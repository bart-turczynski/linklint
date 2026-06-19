import type { Detector } from "./types.js";

/**
 * Ordered list of lexical detectors run by the default `inspect()` path.
 * Epic B fills this in, one vertical slice per detector (FR-D-1..12). The
 * walking skeleton (Epic A) ships with an empty registry — every parsed input
 * is benign by definition until detectors are added.
 */
export const DETECTORS: Detector[] = [];
