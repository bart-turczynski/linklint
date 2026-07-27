/**
 * fp extension — refuse `--status done` without a closing comment.
 *
 * Why this exists (LINK-crxctgsh, from the LINK-nlfybbsf audit of 2026-07-26):
 * across 45 audited issues, closing-comment presence separated good from bad
 * PERFECTLY. LINK-tbqeqqvv, LINK-hastsuzd and LINK-njcklhlg were each closed
 * with zero comments and zero referencing commits — three for three defective,
 * and tbqeqqvv shipped a documented mechanism that was never implemented. Every
 * issue carrying a "merged as PR #N" comment verified clean.
 *
 * The same audit produced an important NEGATIVE result: the "no referencing
 * commit" signature alone fires 59/239 and is ~90% false positive, because the
 * commit-message convention only starts at PR #7. So this guard reads COMMENTS,
 * never the git log.
 *
 * Scope: deliberately a cheap mechanical gate, not a process. Overall the audit
 * found 0 BROKEN issues, so tbqeqqvv is closer to a one-off than a pattern.
 *
 * Source of truth is `tools/fp-extensions/` — `.fp/` is gitignored, so this
 * directory is symlinked into `.fp/extensions/` by `tools/fp-extensions/install.sh`.
 */
import type { ExtensionInit, HookValidationError } from "@fiberplane/extensions";
import { isClosingComment, isTombstoneTitle } from "./predicate.js";

const REJECTION = [
  "Refusing to mark this done: no closing comment names a commit, a PR, or an exemption.",
  "",
  "Add one first, e.g.:",
  '  fp comment <id> "merged as PR #139"',
  '  fp comment <id> "landed in 71debd9"',
  '  fp comment <id> "NO-COMMIT: declined on cost, see the analysis above"',
  "",
  "If this is abandoned or superseded work rather than shipped work, say so in",
  'the title instead: fp issue update --title "[SCRATCHED] ..." <id>',
].join("\n");

const init: ExtensionInit = (fp) => {
  fp.on("issue:status:changing", async ({ issue, to }): Promise<HookValidationError | undefined> => {
    if (to !== "done") return undefined;
    if (isTombstoneTitle(issue.title)) return undefined;

    const comments = await fp.comments.list(issue.id);
    if (comments.some((comment) => isClosingComment(comment.content))) return undefined;

    fp.log.info(`blocked ${issue.id} -> done: no closing comment`);
    return {
      code: "CLOSING_COMMENT_REQUIRED",
      message: REJECTION,
      details: { issueId: issue.id, commentCount: comments.length },
    };
  });
};

export default init;
