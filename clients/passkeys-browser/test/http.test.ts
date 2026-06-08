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

  it("PkAuthHttpError parses JSON body and exposes error/detail/outcome getters", () => {
    const body = JSON.stringify({ error: "invalid_token", detail: "expired", outcome: "failed" });
    const e = new PkAuthHttpError(400, body);
    expect(e.data).toMatchObject({ error: "invalid_token", detail: "expired", outcome: "failed" });
    expect(e.error).toBe("invalid_token");
    expect(e.detail).toBe("expired");
    expect(e.outcome).toBe("failed");
    // raw body still preserved
    expect(e.body).toBe(body);
    expect(e.status).toBe(400);
  });

  it("PkAuthHttpError leaves data/error/detail/outcome undefined for non-JSON body", () => {
    const e = new PkAuthHttpError(503, "Service Unavailable");
    expect(e.data).toBeUndefined();
    expect(e.error).toBeUndefined();
    expect(e.detail).toBeUndefined();
    expect(e.outcome).toBeUndefined();
  });

  it("PkAuthHttpError leaves data undefined when JSON body is not an object", () => {
    const e = new PkAuthHttpError(400, JSON.stringify([1, 2, 3]));
    expect(e.data).toBeUndefined();
  });

  // Gaps surfaced by StrykerJS mutation testing (PR #39, @bernata): each case
  // below kills a mutant that the existing line-covered tests left alive — the
  // code ran, but nothing asserted the behaviour the mutation changed.
  it("PkAuthHttpError leaves data undefined for the JSON literal null", () => {
    // Kills the `parsed !== null && ...` -> `|| ...` mutant: with `||`, a body
    // of "null" (typeof null === "object") would wrongly be treated as data.
    const e = new PkAuthHttpError(400, "null");
    expect(e.data).toBeUndefined();
    expect(e.error).toBeUndefined();
  });

  it("PkAuthHttpError leaves data undefined for a primitive JSON body", () => {
    // Kills the "force the object-check true" mutant: a JSON number is valid
    // JSON but not a record, so data must stay undefined.
    expect(new PkAuthHttpError(400, "5").data).toBeUndefined();
    expect(new PkAuthHttpError(400, '"a string"').data).toBeUndefined();
  });

  it("always sends an accept: application/json header", async () => {
    // Kills the `{ accept: "application/json" }` -> `{}` / "" mutants at the
    // header-initialiser: nothing previously asserted the accept header.
    const fetchImpl = fakeFetch((_url, init) => {
      expect((init.headers as Record<string, string>)["accept"]).toBe("application/json");
      return { status: 200, body: "{}" };
    });
    await request(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      "GET",
      "/p",
      undefined,
      false,
    );
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("omits content-type when there is no request body", async () => {
    // Kills the `if (body !== undefined)` -> always-true mutant: a body-less
    // GET must not advertise a JSON content-type or carry a body.
    const fetchImpl = fakeFetch((_url, init) => {
      expect((init.headers as Record<string, string>)["content-type"]).toBeUndefined();
      expect(init.body).toBeUndefined();
      return { status: 200, body: "{}" };
    });
    await request(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      "GET",
      "/p",
      undefined,
      false,
    );
  });

  it("throws the friendly error (not a TypeError) when getToken is absent", async () => {
    // Kills the optional-chaining mutant `options.getToken?.()` -> `getToken()`:
    // with no getToken at all, the optional call yields a clean validation
    // error; the mutant would throw "getToken is not a function" instead.
    await expect(
      request(
        { apiBase: "https://x" },
        "GET",
        "/path",
        undefined,
        true,
      ),
    ).rejects.toThrow(/requires getToken/);
  });
});
