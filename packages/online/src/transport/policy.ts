export interface TransportPolicy {
  /** Cumulative number of explicitly authorized HTTP requests in one session. */
  readonly maxHops: number;
  /** Cumulative encoded response-body bytes in one session. */
  readonly maxResponseBytes: number;
  /** Cumulative bytes after content decoding in one session. */
  readonly maxDecompressedBytes: number;
  /** Total wall-clock duration of one session, including caller think time. */
  readonly maxTotalTimeMs: number;
  /**
   * Encoded body bytes a destination must deliver in each
   * `minThroughputWindowMs` window while its response body is being read.
   * A window that closes below the floor ends the attempt.
   */
  readonly minThroughputBytes: number;
  /** Length of the throughput window applied while reading a response body. */
  readonly minThroughputWindowMs: number;
}

export const DEFAULT_TRANSPORT_POLICY: TransportPolicy = Object.freeze({
  maxHops: 10,
  maxResponseBytes: 1_048_576,
  maxDecompressedBytes: 4_194_304,
  maxTotalTimeMs: 10_000,
  minThroughputBytes: 512,
  minThroughputWindowMs: 2_000,
});

export function resolveTransportPolicy(
  policy: Partial<TransportPolicy> | undefined,
): TransportPolicy {
  const resolved: TransportPolicy = {
    ...DEFAULT_TRANSPORT_POLICY,
    ...policy,
  };
  requirePositiveInteger("maxHops", resolved.maxHops);
  requirePositiveInteger("maxResponseBytes", resolved.maxResponseBytes);
  requirePositiveInteger("maxDecompressedBytes", resolved.maxDecompressedBytes);
  requirePositiveInteger("maxTotalTimeMs", resolved.maxTotalTimeMs);
  requirePositiveInteger("minThroughputBytes", resolved.minThroughputBytes);
  requirePositiveInteger("minThroughputWindowMs", resolved.minThroughputWindowMs);
  if (resolved.maxTotalTimeMs > 2_147_483_647) {
    throw new RangeError("maxTotalTimeMs exceeds the runtime timer limit");
  }
  if (resolved.minThroughputWindowMs > 2_147_483_647) {
    throw new RangeError("minThroughputWindowMs exceeds the runtime timer limit");
  }
  return Object.freeze(resolved);
}

function requirePositiveInteger(name: keyof TransportPolicy, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
}
