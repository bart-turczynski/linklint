const FORWARDED_REQUEST_HEADERS = new Set([
  "accept",
  "accept-language",
  "user-agent",
]);

/** Build a fresh destination header set; never mutate or spread caller input. */
export function destinationHeaders(
  host: string,
  input: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> {
  const headers: Record<string, string> = {
    host,
    "accept-encoding": "gzip, deflate, br",
  };
  for (const [name, value] of Object.entries(input ?? {})) {
    const normalized = name.toLowerCase();
    if (
      typeof value === "string" &&
      FORWARDED_REQUEST_HEADERS.has(normalized) &&
      !/[\0\r\n]/.test(value)
    ) {
      headers[normalized] = value;
    }
  }
  return headers;
}
