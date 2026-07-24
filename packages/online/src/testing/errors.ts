export type FixtureFailureCode =
  | "dns-not-found"
  | "dns-timeout"
  | "dns-malformed"
  | "connect-refused"
  | "connect-timeout"
  | "tls-handshake"
  | "tls-certificate"
  | "http-malformed"
  | "http-reset"
  | "http-timeout"
  | "decompression-error";

/** A deterministic operational failure emitted by a scripted fixture port. */
export class FixtureFailure extends Error {
  readonly code: FixtureFailureCode;

  constructor(code: FixtureFailureCode) {
    super(`scripted fixture failure: ${code}`);
    this.name = "FixtureFailure";
    this.code = code;
  }
}

/** Raised when code under test makes a call that the fixture did not script. */
export class UnexpectedFixtureCall extends Error {
  readonly port: "resolver" | "connector" | "http" | "tls-observer";

  constructor(port: "resolver" | "connector" | "http" | "tls-observer", detail: string) {
    super(`unexpected ${port} fixture call: ${detail}`);
    this.name = "UnexpectedFixtureCall";
    this.port = port;
  }
}

/** Stable cancellation error used instead of runtime-specific error messages. */
export class FixtureAbortError extends Error {
  constructor() {
    super("fixture operation aborted");
    this.name = "AbortError";
  }
}
