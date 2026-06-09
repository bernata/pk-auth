// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from "vitest";
import { PkAuthAdminClient } from "../src/admin";

function stubFetch(routes: Record<string, (init: RequestInit) => { status: number; body: string }>) {
  return vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = String(url).replace(/^https:\/\/x/, "");
    const handler = routes[path] ?? routes["*"];
    if (!handler) throw new Error("unexpected " + path);
    const { status, body } = handler(init ?? {});
    // jsdom's Response constructor rejects bodies on 204/205; pass null instead.
    const responseBody = status === 204 || status === 205 ? null : body;
    return new Response(responseBody, { status });
  });
}

describe("PkAuthAdminClient", () => {
  it("requires getToken", () => {
    expect(() => new PkAuthAdminClient({ apiBase: "https://x" } as never)).toThrow(/getToken/);
  });

  it("getAccount sends Bearer header to /auth/admin/account", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/account": (init) => {
        const headers = init.headers as Record<string, string>;
        expect(headers["authorization"]).toBe("Bearer t");
        expect(init.method).toBe("GET");
        return {
          status: 200,
          body: JSON.stringify({
            userHandle: "uh",
            username: "alice",
            displayName: "Alice",
            emailVerified: false,
            phoneVerified: false,
            credentialCount: 1,
            backupCodesRemaining: 8,
          }),
        };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const acc = await c.getAccount();
    expect(acc.username).toBe("alice");
  });

  it("listCredentials hits the right path", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/credentials": () => ({ status: 200, body: "[]" }),
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    expect(await c.listCredentials()).toEqual([]);
  });

  it("renameCredential PATCHes with the new label", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/credentials/abc": (init) => {
        expect(init.method).toBe("PATCH");
        expect(JSON.parse(String(init.body))).toEqual({ label: "new" });
        return {
          status: 200,
          body: JSON.stringify({
            credentialId: "abc",
            label: "new",
            createdAt: "2026-01-01T00:00:00Z",
            counter: 0,
            backupEligible: false,
            backupState: false,
            transports: [],
          }),
        };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const updated = await c.renameCredential("abc", "new");
    expect(updated.label).toBe("new");
  });

  it("regenerateBackupCodes POSTs and returns the batch", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/backup-codes/regenerate": (init) => {
        expect(init.method).toBe("POST");
        return { status: 200, body: JSON.stringify({ codes: ["a-b-c", "d-e-f"] }) };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const batch = await c.regenerateBackupCodes();
    expect(batch.codes).toEqual(["a-b-c", "d-e-f"]);
  });

  it("remainingBackupCodes returns the count", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/backup-codes/count": () => ({ status: 200, body: '{"remaining":4}' }),
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    expect(await c.remainingBackupCodes()).toEqual({ remaining: 4 });
  });

  it("startEmailVerification POSTs the email", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/email/start-verification": (init) => {
        expect(JSON.parse(String(init.body))).toEqual({ email: "a@example.com" });
        return { status: 200, body: JSON.stringify({ token: "magic-token" }) };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const result = await c.startEmailVerification("a@example.com");
    expect(result.token).toBe("magic-token");
  });

  it("completePhoneVerification POSTs phone + code", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/phone/complete-verification": (init) => {
        expect(JSON.parse(String(init.body))).toEqual({ phone: "+1555", code: "123456" });
        return {
          status: 200,
          body: JSON.stringify({ phone: "+1555", verified: true }),
        };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const r = await c.completePhoneVerification("+1555", "123456");
    expect(r.verified).toBe(true);
  });

  // Gaps surfaced by StrykerJS mutation testing (PR #39, @bernata):
  //  - completeEmailVerification / startPhoneVerification had no coverage at all
  //    (every mutant in them survived because no test executed them);
  //  - the per-method tests above assert path + verb but (except getAccount)
  //    never assert the Authorization header, so the `authenticated` argument
  //    (the literal `true` on each request() call) could be mutated to `false`
  //    and survive. Driving every method through one bearer-asserting matrix
  //    closes both holes.
  it("completeEmailVerification POSTs the token", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/email/complete-verification": (init) => {
        expect(init.method).toBe("POST");
        expect(JSON.parse(String(init.body))).toEqual({ token: "verify-tok" });
        return { status: 200, body: JSON.stringify({ email: "a@b.c", verified: true }) };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const r = await c.completeEmailVerification("verify-tok");
    expect(r.verified).toBe(true);
  });

  it("startPhoneVerification POSTs the phone", async () => {
    const fetchImpl = stubFetch({
      "/auth/admin/phone/start-verification": (init) => {
        expect(init.method).toBe("POST");
        expect(JSON.parse(String(init.body))).toEqual({ phone: "+1555" });
        return { status: 200, body: JSON.stringify({ phone: "+1555", dispatched: true }) };
      },
    });
    const c = new PkAuthAdminClient({
      apiBase: "https://x",
      getToken: () => "t",
      fetch: fetchImpl as unknown as typeof fetch,
    });
    await c.startPhoneVerification("+1555");
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it.each([
    ["getAccount", "GET", "/auth/admin/account", (c: PkAuthAdminClient) => c.getAccount()],
    ["listCredentials", "GET", "/auth/admin/credentials", (c: PkAuthAdminClient) => c.listCredentials()],
    ["renameCredential", "PATCH", "/auth/admin/credentials/abc", (c: PkAuthAdminClient) => c.renameCredential("abc", "L")],
    ["removeCredential", "DELETE", "/auth/admin/credentials/abc", (c: PkAuthAdminClient) => c.removeCredential("abc")],
    ["regenerateBackupCodes", "POST", "/auth/admin/backup-codes/regenerate", (c: PkAuthAdminClient) => c.regenerateBackupCodes()],
    ["remainingBackupCodes", "GET", "/auth/admin/backup-codes/count", (c: PkAuthAdminClient) => c.remainingBackupCodes()],
    ["startEmailVerification", "POST", "/auth/admin/email/start-verification", (c: PkAuthAdminClient) => c.startEmailVerification("a@b.c")],
    ["completeEmailVerification", "POST", "/auth/admin/email/complete-verification", (c: PkAuthAdminClient) => c.completeEmailVerification("tok")],
    ["startPhoneVerification", "POST", "/auth/admin/phone/start-verification", (c: PkAuthAdminClient) => c.startPhoneVerification("+1")],
    ["completePhoneVerification", "POST", "/auth/admin/phone/complete-verification", (c: PkAuthAdminClient) => c.completePhoneVerification("+1", "000")],
  ] as const)(
    "%s calls %s %s as an authenticated (bearer) request",
    async (_name, method, path, call) => {
      const seen: { method?: string; auth?: string; path?: string } = {};
      const recordingFetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
        seen.path = String(url).replace(/^https:\/\/x/, "");
        seen.method = init?.method;
        seen.auth = (init?.headers as Record<string, string> | undefined)?.["authorization"];
        return new Response("{}", { status: 200 });
      });
      const c = new PkAuthAdminClient({
        apiBase: "https://x",
        getToken: () => "bearer-tok",
        fetch: recordingFetch as unknown as typeof fetch,
      });
      await call(c);
      expect(seen.path).toBe(path);
      expect(seen.method).toBe(method);
      // The whole point: every admin call must carry the bearer token. If the
      // `authenticated` flag is flipped to false, this header disappears.
      expect(seen.auth).toBe("Bearer bearer-tok");
    },
  );
});
