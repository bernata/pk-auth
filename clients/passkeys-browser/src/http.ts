// SPDX-License-Identifier: MIT

import type { ClientOptions } from "./types";

export class PkAuthHttpError extends Error {
  readonly status: number;
  readonly body: string;
  readonly data: Record<string, unknown> | undefined;

  constructor(status: number, body: string) {
    super(`HTTP ${status}: ${body}`);
    this.name = "PkAuthHttpError";
    this.status = status;
    this.body = body;
    try {
      const parsed = JSON.parse(body);
      this.data = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : undefined;
    } catch {
      this.data = undefined;
    }
  }

  /** The `error` field from the parsed response body, if present. */
  get error(): string | undefined {
    return typeof this.data?.["error"] === "string" ? (this.data["error"] as string) : undefined;
  }

  /** The `detail` field from the parsed response body, if present. */
  get detail(): string | undefined {
    return typeof this.data?.["detail"] === "string" ? (this.data["detail"] as string) : undefined;
  }

  /** The `outcome` field from the parsed response body, if present. */
  get outcome(): string | undefined {
    return typeof this.data?.["outcome"] === "string" ? (this.data["outcome"] as string) : undefined;
  }
}

/** Internal request wrapper. `authenticated: true` adds the bearer header from `getToken`. */
export async function request<T>(
  options: ClientOptions,
  method: string,
  path: string,
  body: unknown,
  authenticated: boolean,
): Promise<T> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const base = options.apiBase.endsWith("/")
    ? options.apiBase.slice(0, -1)
    : options.apiBase;
  const url = `${base}${path}`;

  const headers: Record<string, string> = { accept: "application/json" };
  let payload: BodyInit | undefined;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (authenticated) {
    const token = options.getToken?.();
    if (!token) {
      throw new Error("pk-auth: authenticated request requires getToken() to return a bearer token");
    }
    headers["authorization"] = `Bearer ${token}`;
  }

  const init: RequestInit = { method, headers };
  if (payload !== undefined) init.body = payload;
  const response = await fetchImpl(url, init);

  const text = await response.text();
  if (!response.ok) {
    throw new PkAuthHttpError(response.status, text);
  }
  if (!text.length) {
    return undefined as unknown as T;
  }
  return JSON.parse(text) as T;
}
