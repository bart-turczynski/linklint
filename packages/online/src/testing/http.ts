import type { ClockPort } from "./clock.js";
import { UnexpectedFixtureCall } from "./errors.js";
import { runFixtureStep, type FixtureStep } from "./script.js";

export type HttpMethod = "GET" | "HEAD";

export interface HttpRequest {
  readonly connectionId: string;
  readonly url: string;
  readonly method: HttpMethod;
  readonly headers?: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, readonly string[]>>;
  readonly body: AsyncIterable<Uint8Array>;
}

export interface HttpPort {
  request(request: HttpRequest): Promise<HttpResponse>;
}

export interface HttpExpectation {
  readonly connectionId: string;
  readonly url: string;
  readonly method: HttpMethod;
  readonly headers?: Readonly<Record<string, string>>;
  readonly absentHeaders?: readonly string[];
}

export interface HttpBodyChunk {
  readonly bytes: Uint8Array | string;
  readonly delayMs?: number;
}

export interface HttpResponseFixture {
  readonly status: number;
  readonly headers?: Readonly<Record<string, string | readonly string[]>>;
  readonly body?: Uint8Array | string | readonly HttpBodyChunk[];
}

export interface HttpFixtureStep extends FixtureStep<HttpResponseFixture> {
  readonly expect: HttpExpectation;
}

export interface HttpCall {
  readonly connectionId: string;
  readonly url: string;
  readonly method: HttpMethod;
  readonly headers: Readonly<Record<string, string>>;
  readonly abortedAtCall: boolean;
}

export class FixtureBody implements AsyncIterable<Uint8Array> {
  private readonly chunks: readonly HttpBodyChunk[];
  private consumed = false;
  chunksRead = 0;
  bytesRead = 0;

  constructor(
    chunks: readonly HttpBodyChunk[],
    private readonly clock: ClockPort,
    private readonly signal?: AbortSignal,
  ) {
    this.chunks = chunks;
  }

  async *[Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    if (this.consumed) throw new Error("fixture response body can only be consumed once");
    this.consumed = true;
    for (const chunk of this.chunks) {
      await this.clock.sleep(chunk.delayMs ?? 0, this.signal);
      const bytes = typeof chunk.bytes === "string" ? new TextEncoder().encode(chunk.bytes) : chunk.bytes;
      this.chunksRead++;
      this.bytesRead += bytes.byteLength;
      yield new Uint8Array(bytes);
    }
  }
}

export class FixtureHttp implements HttpPort {
  readonly calls: HttpCall[] = [];
  readonly bodies: FixtureBody[] = [];
  private readonly steps: HttpFixtureStep[];

  constructor(
    steps: readonly HttpFixtureStep[],
    private readonly clock: ClockPort,
  ) {
    this.steps = [...steps];
  }

  async request(request: HttpRequest): Promise<HttpResponse> {
    const call: HttpCall = {
      connectionId: request.connectionId,
      url: request.url,
      method: request.method,
      headers: normalizeRequestHeaders(request.headers),
      abortedAtCall: request.signal?.aborted ?? false,
    };
    this.calls.push(call);

    const step = this.steps.shift();
    if (!step) throw new UnexpectedFixtureCall("http", `${request.method} ${request.url}`);
    const mismatch = firstRequestMismatch(step.expect, call);
    if (mismatch) throw new UnexpectedFixtureCall("http", mismatch);

    const response = await runFixtureStep(step, this.clock, request.signal);
    const body = new FixtureBody(bodyChunks(response.body), this.clock, request.signal);
    this.bodies.push(body);
    return {
      status: response.status,
      headers: normalizeResponseHeaders(response.headers),
      body,
    };
  }

  get remainingStepCount(): number {
    return this.steps.length;
  }
}

function normalizeRequestHeaders(
  headers: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    normalized[name.toLowerCase()] = value;
  }
  return normalized;
}

function normalizeResponseHeaders(
  headers: Readonly<Record<string, string | readonly string[]>> | undefined,
): Readonly<Record<string, readonly string[]>> {
  const normalized: Record<string, readonly string[]> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    normalized[name.toLowerCase()] = typeof value === "string" ? [value] : [...value];
  }
  return normalized;
}

function bodyChunks(
  body: HttpResponseFixture["body"],
): readonly HttpBodyChunk[] {
  if (body === undefined) return [];
  if (typeof body === "string" || body instanceof Uint8Array) return [{ bytes: body }];
  return body;
}

function firstRequestMismatch(expected: HttpExpectation, actual: HttpCall): string | null {
  for (const key of ["connectionId", "url", "method"] as const) {
    if (expected[key] !== actual[key]) {
      return `${key}: expected ${expected[key]}, received ${actual[key]}`;
    }
  }
  const expectedHeaders = normalizeRequestHeaders(expected.headers);
  for (const [name, value] of Object.entries(expectedHeaders)) {
    if (actual.headers[name] !== value) {
      return `header ${name}: expected ${value}, received ${String(actual.headers[name])}`;
    }
  }
  for (const name of expected.absentHeaders ?? []) {
    const normalized = name.toLowerCase();
    if (normalized in actual.headers) return `header ${normalized}: expected absent`;
  }
  return null;
}
