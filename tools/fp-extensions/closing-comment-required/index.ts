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
import { execFileSync } from "node:child_process";
import type { ExtensionInit, HookValidationError } from "@fiberplane/extensions";
import { classifyClosingComment, isTombstoneTitle } from "./predicate.js";

/**
 * The trunk a commit has to be reachable from before it counts as shipped.
 * Local, deliberately: this repository's push is blocked, so work lands on
 * local `main` by fast-forward and there is no remote to consult.
 */
const TRUNK = "main";

type Reachability = "reachable" | "unreachable" | "unknown-commit" | "no-git";

/**
 * Is `sha` an ancestor of the trunk?
 *
 * `no-git` (not a repo, git missing, no `main`) means the guard cannot form an
 * opinion and MUST NOT block — an unusable tracker is worse than an unverified
 * close, and this failure mode is environmental rather than a workflow slip.
 * `unknown-commit` and `unreachable` are genuine findings and do block.
 */
function reachableFromTrunk(sha: string): Reachability {
  const git = (...args: string[]): string =>
    execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  try {
    git("rev-parse", "--git-dir");
    git("rev-parse", "--verify", `${TRUNK}^{commit}`);
  } catch {
    return "no-git";
  }
  try {
    git("rev-parse", "--verify", `${sha}^{commit}`);
  } catch {
    return "unknown-commit";
  }
  try {
    git("merge-base", "--is-ancestor", sha, TRUNK);
    return "reachable";
  } catch {
    return "unreachable";
  }
}

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

function unmergedRejection(results: readonly (readonly [string, Reachability])[]): string {
  const lines = results.map(([sha, r]) =>
    r === "unknown-commit"
      ? `  ${sha} — no such commit in this repository`
      : `  ${sha} — exists, but is not an ancestor of ${TRUNK}`,
  );
  return [
    `Refusing to mark this done: the closing comment names a commit that has not`,
    `reached ${TRUNK}.`,
    "",
    ...lines,
    "",
    "`done` means shipped. Committing on a branch and closing the issue is what",
    "stranded nine branches and twelve issues (LINK-wgsbhovi, LINK-nwqrqjdc).",
    "",
    "Merge it first, then close:",
    `  git checkout ${TRUNK} && git merge --ff-only <branch>`,
    "",
    "If this legitimately closes without a merged commit, say why:",
    '  fp comment <id> "NO-COMMIT: declined on cost, see the analysis above"',
  ].join("\n");
}

const init: ExtensionInit = (fp) => {
  fp.on("issue:status:changing", async ({ issue, to }): Promise<HookValidationError | undefined> => {
    if (to !== "done") return undefined;
    if (isTombstoneTitle(issue.title)) return undefined;

    const comments = await fp.comments.list(issue.id);
    const verdicts = comments.map((comment) => classifyClosingComment(comment.content));

    // A PR reference or a stated exemption discharges on its own.
    if (verdicts.some((v) => v.kind === "pr" || v.kind === "exempt")) return undefined;

    const shas = verdicts.flatMap((v) => v.shas);
    if (shas.length === 0) {
      fp.log.info(`blocked ${issue.id} -> done: no closing comment`);
      return {
        code: "CLOSING_COMMENT_REQUIRED",
        message: REJECTION,
        details: { issueId: issue.id, commentCount: comments.length },
      };
    }

    // A named commit is not a shipped commit (LINK-nwqrqjdc). Twelve issues
    // were closed citing a SHA that sat on a branch nobody ever merged, and
    // this guard passed every one of them because it only checked that a SHA
    // was NAMED. Reachability from the trunk is the part that means "shipped".
    const results = shas.map((sha) => [sha, reachableFromTrunk(sha)] as const);
    if (results.some(([, r]) => r === "reachable" || r === "no-git")) return undefined;

    fp.log.info(`blocked ${issue.id} -> done: ${shas.join(", ")} not on ${TRUNK}`);
    return {
      code: "CLOSING_COMMIT_NOT_MERGED",
      message: unmergedRejection(results),
      details: { issueId: issue.id, shas, trunk: TRUNK },
    };
  });
};

export default init;
