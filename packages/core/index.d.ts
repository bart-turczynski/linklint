/**
 * linklint — explainable, offline-first URL inspector.
 *
 * Placeholder release (0.0.2). The full result schema (`InspectResult`) and
 * options type land with the implementation; see docs/architecture.md §6.
 */
export interface InspectOptions {}

export interface InspectResult {
  schemaVersion: string;
  status: 'ok' | 'invalid';
  [key: string]: unknown;
}

/**
 * Inspect a single URL or bare hostname and return an explainable verdict.
 * Synchronous and offline by design. Not implemented in this placeholder release.
 */
export function inspect(input: string, options?: InspectOptions): InspectResult;
