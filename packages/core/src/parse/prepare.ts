/**
 * Input preparation (FR-IN-1, architecture §4.1.1). Preserve the original input
 * upstream; here we only trim surrounding whitespace to get a parse candidate.
 */
export function prepare(input: string): string {
  return input.trim();
}
