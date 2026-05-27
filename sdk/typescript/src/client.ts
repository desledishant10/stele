// HTTP client for stele's JSON API.
//
// Uses globalThis.fetch — present in Node ≥18 and every browser.
// No third-party deps.

export class HTTPError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string) {
    super(`HTTP ${status}: ${body.slice(0, 1024)}`);
    this.status = status;
    this.body = body;
  }
}

export interface SteleClientOptions {
  baseUrl: string;
  /** Per-request timeout in ms. Default 15000. */
  timeoutMs?: number;
  /** Optional headers added to every request. */
  headers?: Record<string, string>;
  /** Pluggable fetch (for tests / custom TLS / browser-vs-node). */
  fetchImpl?: typeof fetch;
}

export class SteleClient {
  readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: SteleClientOptions) {
    if (!opts.baseUrl) {
      throw new Error("SteleClient: baseUrl required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.headers = { ...(opts.headers ?? {}) };
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error(
        "SteleClient: no fetch implementation available — pass opts.fetchImpl",
      );
    }
  }

  get<T = unknown>(path: string): Promise<T> {
    return this.call<T>("GET", path);
  }

  post<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.call<T>("POST", path, body);
  }

  private async call<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<T> {
    const ctl = new AbortController();
    const timeout = setTimeout(() => ctl.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...this.headers,
    };
    let payload: BodyInit | undefined;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
    }
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: payload,
        signal: ctl.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!resp.ok) {
      const txt = await resp.text().catch(() => "");
      throw new HTTPError(resp.status, txt);
    }
    if (resp.status === 204) {
      return undefined as T;
    }
    return (await resp.json()) as T;
  }
}
