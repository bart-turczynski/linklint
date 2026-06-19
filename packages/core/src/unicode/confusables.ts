import type { Confusable, ConfusableComponent } from "../schema/types.js";
import { CONFUSABLES } from "../data/confusables.js";
import { codepointOf } from "./format-chars.js";

/**
 * Scan a string for confusable characters (FR-D-2 / FR-D-12). Position is the
 * codepoint index within the scanned component. Informational only — the engine
 * annotates which characters are confusable; it never scores (FR-D-16).
 */
export function findConfusables(input: string, component: ConfusableComponent): Confusable[] {
  const out: Confusable[] = [];
  let position = 0;
  for (const ch of input) {
    const hit = CONFUSABLES.get(ch);
    if (hit) {
      out.push({
        char: ch,
        codepoint: codepointOf(ch),
        confusableWith: hit.confusableWith,
        component,
        position,
      });
    }
    position++;
  }
  return out;
}
