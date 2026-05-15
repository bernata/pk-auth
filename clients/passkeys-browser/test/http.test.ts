// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from "vitest";
import { PkAuthHttpError, request } from "../src/http";

function fakeFetch(handler: (url: string, init: RequestInit) => { status: number; body: string }) {
  return vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(String(url), init ?? {});
    return new Response(body, { status });
  });
}

describe("request()", () => {
  it("strips trailing slash on apiBase", async () => {
    const fetchImpl = fakeFetch((url) => {
      expect(url).toBe("https://x.example/auth/admin/account");
      return { status: 200, body: JSON.stringify({ ok: true }) };
    });
    await request(
      { apiBase: "https://x.example/", getToken: () => "tok", fetch: fetchImpl as unknown as typeof fetch },
      "GET",
      "/auth/admin/account",
      undefined,
      true,
    );
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("adds Authorization header when authenticated=true", async () => {
    const fetchImpl = fakeFetch((_url, init) => {
      const headers = init.headers as Record<string, string>;
      expect(headers["authorization"]).toBe("Bearer t-1");
      return { status: 200, body: "{}" };
    });
    await request(
      { apiBase: "https://x", getToken: () => "t-1", fetch: fetchImpl as unknown as typeof fetch },
      "GET",
      "/path",
      undefined,
      true,
    );
  });

  it("throws when authenticated but no token", async () => {
    await expect(
      request(
        { apiBase: "https://x", getToken: () => null },
        "GET",
        "/path",
        undefined,
        true,
      ),
    ).rejects.toThrow(/requires getToken/);
  });

  it("serializes JSON body and sets content-type", async () => {
    const fetchImpl = fakeFetch((_url, init) => {
      expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
      expect(init.body).toBe(JSON.stringify({ a: 1 }));
      return { status: 200, body: '{"ok":true}' };
    });
    await request(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      "POST",
      "/p",
      { a: 1 },
      false,
    );
  });

  it("throws PkAuthHttpError on non-2xx", async () => {
    const fetchImpl = fakeFetch(() => ({ status: 404, body: "nope" }));
    await expect(
      request(
        { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
        "GET",
        "/p",
        undefined,
        false,
      ),
    ).rejects.toMatchObject({ name: "PkAuthHttpError", status: 404, body: "nope" });
  });

  it("returns undefined for empty body", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    const result = await request<void>(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      "DELETE",
      "/p",
      undefined,
      false,
    );
    expect(result).toBeUndefined();
  });

  it("PkAuthHttpError surfaces status + body on .message", () => {
    const e = new PkAuthHttpError(500, "boom");
    expect(e.message).toContain("500");
    expect(e.message).toContain("boom");
  });
});
