import { FixtureAbortError } from "./errors.js";

export interface ClockPort {
  now(): Date;
  sleep(delayMs: number, signal?: AbortSignal): Promise<void>;
}

interface PendingSleep {
  readonly id: number;
  readonly dueAtMs: number;
  readonly resolve: () => void;
  readonly signal: AbortSignal | undefined;
  readonly onAbort: (() => void) | undefined;
}

/**
 * Manually advanced clock. It never reads wall time or creates real timers.
 * Equal-deadline sleeps settle in creation order.
 */
export class FixtureClock implements ClockPort {
  private currentMs: number;
  private nextId = 0;
  private pending: PendingSleep[] = [];

  constructor(start: string | number | Date = "2026-01-01T00:00:00.000Z") {
    const initial = start instanceof Date ? start.getTime() : new Date(start).getTime();
    if (!Number.isFinite(initial)) {
      throw new RangeError("fixture clock start must be a valid instant");
    }
    this.currentMs = initial;
  }

  now(): Date {
    return new Date(this.currentMs);
  }

  get pendingSleepCount(): number {
    return this.pending.length;
  }

  sleep(delayMs: number, signal?: AbortSignal): Promise<void> {
    if (!Number.isFinite(delayMs) || delayMs < 0) {
      return Promise.reject(new RangeError("fixture delay must be finite and non-negative"));
    }
    if (signal?.aborted) return Promise.reject(new FixtureAbortError());
    if (delayMs === 0) return Promise.resolve();

    return new Promise<void>((resolve, reject) => {
      const id = this.nextId++;
      const onAbort = signal
        ? () => {
            const pending = this.remove(id);
            if (pending) reject(new FixtureAbortError());
          }
        : undefined;
      const sleep: PendingSleep = {
        id,
        dueAtMs: this.currentMs + delayMs,
        resolve,
        signal,
        onAbort,
      };
      this.pending.push(sleep);
      this.pending.sort((left, right) => left.dueAtMs - right.dueAtMs || left.id - right.id);
      signal?.addEventListener("abort", onAbort!, { once: true });
    });
  }

  advanceBy(delayMs: number): void {
    if (!Number.isFinite(delayMs) || delayMs < 0) {
      throw new RangeError("fixture clock advance must be finite and non-negative");
    }
    this.advanceTo(this.currentMs + delayMs);
  }

  advanceTo(instant: string | number | Date): void {
    const target = instant instanceof Date ? instant.getTime() : new Date(instant).getTime();
    if (!Number.isFinite(target) || target < this.currentMs) {
      throw new RangeError("fixture clock cannot move backwards or to an invalid instant");
    }

    this.currentMs = target;
    const ready = this.pending.filter((sleep) => sleep.dueAtMs <= target);
    this.pending = this.pending.filter((sleep) => sleep.dueAtMs > target);
    for (const sleep of ready) {
      this.detachAbortListener(sleep);
      sleep.resolve();
    }
  }

  runAll(): void {
    const final = this.pending.at(-1)?.dueAtMs;
    if (final !== undefined) this.advanceTo(final);
  }

  private remove(id: number): PendingSleep | undefined {
    const index = this.pending.findIndex((sleep) => sleep.id === id);
    if (index === -1) return undefined;
    const [sleep] = this.pending.splice(index, 1);
    if (sleep) this.detachAbortListener(sleep);
    return sleep;
  }

  private detachAbortListener(sleep: PendingSleep): void {
    if (sleep.signal && sleep.onAbort) {
      sleep.signal.removeEventListener("abort", sleep.onAbort);
    }
  }
}
