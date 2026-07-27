/**
 * The closing-comment predicate, kept free of any `@fiberplane/extensions`
 * import so it typechecks and unit-tests inside the repo's normal `pnpm check`
 * chain. The fp runtime wiring lives in `./index.ts`.
 *
 * See `./index.ts` for why this guard exists (LINK-crxctgsh).
 */

/** A PR or issue reference: `#139`, `PR #139`, `pull request 139`. */
const PR_REF = /(?:^|[^\w#])#\d+|(?:\bPR|\bpull request)\s*#?\s*\d+/i;

/**
 * A git SHA: 7-40 hex chars with at least one a-f digit, so bare numbers
 * ("1234567 URLs in the corpus") do not read as a commit.
 */
const SHA_REF = /\b(?=[0-9a-f]{7,40}\b)[0-9a-f]*[a-f][0-9a-f]*\b/i;

/**
 * Escape hatch for closes that legitimately have no commit — declined
 * proposals, superseded work, epics closing on their children's acceptance.
 * Requires a stated reason, so the exemption stays auditable rather than
 * becoming a silent bypass.
 */
const NO_COMMIT = /\bNO-COMMIT:\s*\S+/;

/** Does this comment body discharge the closing-comment requirement? */
export function isClosingComment(content: string): boolean {
  return PR_REF.test(content) || SHA_REF.test(content) || NO_COMMIT.test(content);
}
