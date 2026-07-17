import type { ClockPort } from "./types.js";

class ClockAbortError extends Error {
  constructor() {
    super("clock sleep aborted");
    this.name = "AbortError";
  }
}

export class SystemClock implements ClockPort {
  now(): Date {
    return new Date();
  }

  sleep(delayMs: number, signal?: AbortSignal): Promise<void> {
    if (!Number.isFinite(delayMs) || delayMs < 0) {
      return Promise.reject(new RangeError("delay must be finite and non-negative"));
    }
    if (signal?.aborted) return Promise.reject(new ClockAbortError());
    return new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer);
        reject(new ClockAbortError());
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
}
