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
  /**
   * Response-header block bytes accepted from a destination on ONE hop.
   *
   * Per-hop rather than cumulative, unlike the body budgets: a header block is
   * a per-response resource, and a session that spent its encoded-byte budget
   * on bodies would otherwise leave every head unbounded. The default restates
   * Node's own `--max-http-header-size` so the limit belongs to this boundary
   * rather than to whatever the host process was launched with.
   */
  readonly maxResponseHeaderBytes: number;
  /**
   * Response header FIELD OCCURRENCES accepted from a destination on one hop.
   *
   * A separate axis from {@link maxResponseHeaderBytes} because the HTTP parser
   * caps total header bytes, not field count — thousands of four-byte fields
   * fit inside a byte cap and still cost a map entry each.
   */
  readonly maxResponseHeaderFields: number;
}

export const DEFAULT_TRANSPORT_POLICY: TransportPolicy = Object.freeze({
  maxHops: 10,
  maxResponseBytes: 1_048_576,
  maxDecompressedBytes: 4_194_304,
  maxTotalTimeMs: 10_000,
  minThroughputBytes: 512,
  minThroughputWindowMs: 2_000,
  maxResponseHeaderBytes: 16_384,
  maxResponseHeaderFields: 128,
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
  requirePositiveInteger("maxResponseHeaderBytes", resolved.maxResponseHeaderBytes);
  requirePositiveInteger("maxResponseHeaderFields", resolved.maxResponseHeaderFields);
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
