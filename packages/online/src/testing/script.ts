import type { ClockPort } from "./clock.js";
import { FixtureFailure, type FixtureFailureCode } from "./errors.js";

export type FixtureOutcome<T> =
  | { readonly value: T; readonly failure?: never }
  | { readonly value?: never; readonly failure: FixtureFailureCode };

export interface FixtureStep<T> {
  readonly delayMs?: number;
  readonly outcome: FixtureOutcome<T>;
}

export async function runFixtureStep<T>(
  step: FixtureStep<T>,
  clock: ClockPort,
  signal?: AbortSignal,
): Promise<T> {
  await clock.sleep(step.delayMs ?? 0, signal);
  if (step.outcome.failure) throw new FixtureFailure(step.outcome.failure);
  return step.outcome.value;
}
