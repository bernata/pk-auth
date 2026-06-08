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

  // Gaps surfaced by StrykerJS mutation testing (PR #39, @bernata): the suite
  // above only pinned the positive branch of each guard / path, so mutations of
  // the negative branch survived. Closing them here.
  it("type guards reject the opposite variant", () => {
    // Kills the `r.kind === "success"` / `=== "failure"` -> always-true mutants:
    // a guard that returns true for everything is broken but was untested.
    const ok = { kind: "success", accessToken: "a", refreshToken: "r", expiresAt: "t" } as const;
    const bad = { kind: "failure", reason: "expired" } as const;
    expect(isRefreshSuccess(bad)).toBe(false);
    expect(isRefreshFailure(ok)).toBe(false);
  });

  it("posts to the default /auth/refresh path when none is given", async () => {
    // Kills the default-parameter mutant `path = "/auth/refresh"` -> `= ""`:
    // nothing previously asserted the URL the default client actually calls.
    let calledUrl = "";
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) => {
      calledUrl = String(url);
      return new Response(
        JSON.stringify({ refreshToken: "n", accessToken: "a", expiresAt: "t" }),
        { status: 200 },
      );
    });
    const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
    await client.refresh("old.token");
    expect(calledUrl).toBe("https://x/auth/refresh");
  });

  it("falls back to 'unknown' (without throwing) on a 401 with a non-JSON body", async () => {
    // Kills the optional-chaining mutant `e.data?.detail` -> `e.data.detail`:
    // a 401 whose body is not JSON leaves e.data undefined, so the mutant would
    // throw a TypeError instead of returning the conservative failure.
    const fetchImpl = stubFetch(() => ({ status: 401, body: "Unauthorized" }));
    const client = new PkAuthRefreshClient({ apiBase: "https://x", fetch: fetchImpl } as never);
    const result = await client.refresh("old.token");
    expect(isRefreshFailure(result)).toBe(true);
    if (isRefreshFailure(result)) {
      expect(result.reason).toBe("unknown");
    }
  });
});
