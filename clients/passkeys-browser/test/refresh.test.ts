// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from "vitest";
import { isRefreshFailure, isRefreshSuccess, PkAuthRefreshClient } from "../src/refresh";

function stubFetch(handler: (init: RequestInit) => { status: number; body: string }) {
  return vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(init ?? {});
    return new Response(body, { status });
  });
}

describe("PkAuthRefreshClient", () => {
  it("returns RefreshSuccess on 200", async () => {
    const fetchImpl = stubFetch((init) => {
      expect(init.method).toBe("POST");
      const body = JSON.parse(String(init.body));
      expect(body).toEqual({ refreshToken: "old.token" });
      return {
        status: 200,
        body: JSON.stringify({
          refreshToken: "new.token",
          accessToken: "jwt-blob",
          expiresAt: "2026-06-01T00:00:00Z",
        }),
      };
    });

    const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
    const result = await client.refresh("old.token");

    expect(isRefreshSuccess(result)).toBe(true);
    if (isRefreshSuccess(result)) {
      expect(result.accessToken).toBe("jwt-blob");
      expect(result.refreshToken).toBe("new.token");
      expect(result.expiresAt).toBe("2026-06-01T00:00:00Z");
    }
  });

  it.each(["expired", "unknown", "replayed", "revoked"] as const)(
    "maps 401 with detail=%s to a typed RefreshFailure",
    async (detail) => {
      const fetchImpl = stubFetch(() => ({
        status: 401,
        body: JSON.stringify({ detail }),
      }));
      const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
      const result = await client.refresh("old.token");
      expect(isRefreshFailure(result)).toBe(true);
      if (isRefreshFailure(result)) {
        expect(result.reason).toBe(detail);
      }
    },
  );

  it("surfaces revokeReason when present", async () => {
    const fetchImpl = stubFetch(() => ({
      status: 401,
      body: JSON.stringify({ detail: "revoked", reason: "USER_DELETED" }),
    }));
    const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
    const result = await client.refresh("old.token");
    expect(isRefreshFailure(result)).toBe(true);
    if (isRefreshFailure(result)) {
      expect(result.reason).toBe("revoked");
      expect(result.revokeReason).toBe("USER_DELETED");
    }
  });

  it("falls back to 'unknown' on 401 with no/unfamiliar detail", async () => {
    const fetchImpl = stubFetch(() => ({ status: 401, body: "{}" }));
    const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
    const result = await client.refresh("old.token");
    expect(isRefreshFailure(result)).toBe(true);
    if (isRefreshFailure(result)) {
      expect(result.reason).toBe("unknown");
    }
  });

  it("rethrows non-401 HTTP errors", async () => {
    const fetchImpl = stubFetch(() => ({ status: 500, body: "boom" }));
    const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
    await expect(client.refresh("old.token")).rejects.toThrow(/HTTP 500/);
  });
});
