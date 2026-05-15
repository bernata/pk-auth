// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from "vitest";
import * as b64u from "../src/base64url";
import {
  PkAuthCeremonyClient,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAuthenticationResponse,
  encodeRegistrationResponse,
} from "../src/ceremonies";
import type {
  PublicKeyCredentialCreationOptionsJson,
  PublicKeyCredentialRequestOptionsJson,
} from "../src/types";

const CREATE_OPTIONS_JSON: PublicKeyCredentialCreationOptionsJson = {
  rp: { id: "example.com", name: "Example" },
  user: {
    id: b64u.encode(new Uint8Array([1, 2, 3, 4])),
    name: "alice",
    displayName: "Alice",
  },
  challenge: b64u.encode(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd])),
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  timeout: 60_000,
  attestation: "none",
};

const REQUEST_OPTIONS_JSON: PublicKeyCredentialRequestOptionsJson = {
  challenge: b64u.encode(new Uint8Array([1, 1, 1, 1])),
  rpId: "example.com",
  userVerification: "preferred",
  allowCredentials: [
    {
      id: b64u.encode(new Uint8Array([9, 8, 7])),
      type: "public-key",
      transports: ["internal"],
    },
  ],
};

function fakeCredential(rawId: Uint8Array, response: AuthenticatorResponse): PublicKeyCredential {
  return {
    rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.byteLength) as ArrayBuffer,
    id: b64u.encode(rawId),
    type: "public-key",
    authenticatorAttachment: null,
    getClientExtensionResults: () => ({}),
    response,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential;
}

describe("decodeCreationOptions", () => {
  it("base64url-decodes challenge and user.id", () => {
    const decoded = decodeCreationOptions(CREATE_OPTIONS_JSON);
    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(
      new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    );
    expect(new Uint8Array(decoded.user.id as ArrayBuffer)).toEqual(
      new Uint8Array([1, 2, 3, 4]),
    );
    expect(decoded.rp).toEqual({ id: "example.com", name: "Example" });
    expect(decoded.attestation).toBe("none");
  });
});

describe("decodeRequestOptions", () => {
  it("base64url-decodes challenge and allowCredentials ids", () => {
    const decoded = decodeRequestOptions(REQUEST_OPTIONS_JSON);
    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(
      new Uint8Array([1, 1, 1, 1]),
    );
    const ac = decoded.allowCredentials![0]!;
    expect(new Uint8Array(ac.id as ArrayBuffer)).toEqual(new Uint8Array([9, 8, 7]));
  });
});

describe("encodeRegistrationResponse", () => {
  it("encodes attestation + clientDataJSON + transports", () => {
    const rawId = new Uint8Array([5, 6, 7]);
    const clientData = new Uint8Array([0x7b]); // "{"
    const attestation = new Uint8Array([0xa0]);
    const credential = fakeCredential(rawId, {
      clientDataJSON: clientData.buffer as ArrayBuffer,
      attestationObject: attestation.buffer as ArrayBuffer,
      getTransports: () => ["internal", "hybrid"],
    } as unknown as AuthenticatorResponse);
    const encoded = encodeRegistrationResponse(credential);
    expect(encoded.id).toBe(b64u.encode(rawId));
    expect(encoded.rawId).toBe(b64u.encode(rawId));
    expect(encoded.type).toBe("public-key");
    expect(encoded.response.clientDataJSON).toBe(b64u.encode(clientData));
    expect(encoded.response.attestationObject).toBe(b64u.encode(attestation));
    expect(encoded.response.transports).toEqual(["internal", "hybrid"]);
  });

  it("falls back to empty transports when getTransports is absent", () => {
    const rawId = new Uint8Array([1]);
    const credential = fakeCredential(rawId, {
      clientDataJSON: new Uint8Array([0]).buffer as ArrayBuffer,
      attestationObject: new Uint8Array([0]).buffer as ArrayBuffer,
    } as unknown as AuthenticatorResponse);
    const encoded = encodeRegistrationResponse(credential);
    expect(encoded.response.transports).toEqual([]);
  });
});

describe("encodeAuthenticationResponse", () => {
  it("encodes assertion response and a null userHandle", () => {
    const rawId = new Uint8Array([2]);
    const credential = fakeCredential(rawId, {
      clientDataJSON: new Uint8Array([0x7b]).buffer as ArrayBuffer,
      authenticatorData: new Uint8Array([0x55]).buffer as ArrayBuffer,
      signature: new Uint8Array([0x99]).buffer as ArrayBuffer,
      userHandle: null,
    } as unknown as AuthenticatorResponse);
    const encoded = encodeAuthenticationResponse(credential);
    expect(encoded.response.userHandle).toBeNull();
    expect(encoded.response.signature).toBe(b64u.encode(new Uint8Array([0x99])));
  });

  it("encodes a present userHandle", () => {
    const handle = new Uint8Array([0xab, 0xcd]);
    const credential = fakeCredential(new Uint8Array([3]), {
      clientDataJSON: new Uint8Array([0]).buffer as ArrayBuffer,
      authenticatorData: new Uint8Array([0]).buffer as ArrayBuffer,
      signature: new Uint8Array([0]).buffer as ArrayBuffer,
      userHandle: handle.buffer as ArrayBuffer,
    } as unknown as AuthenticatorResponse);
    expect(encodeAuthenticationResponse(credential).response.userHandle).toBe(b64u.encode(handle));
  });
});

describe("PkAuthCeremonyClient.register (end-to-end with stubbed credentials)", () => {
  it("walks start -> create -> finish, propagating the challenge id", async () => {
    const startBody: PublicKeyCredentialCreationOptionsJson = CREATE_OPTIONS_JSON;
    const fetchImpl = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).endsWith("/registration/start")) {
        return new Response(
          JSON.stringify({ challengeId: "ch-1", publicKey: startBody }),
          { status: 200 },
        );
      }
      if (String(url).endsWith("/registration/finish")) {
        const body = JSON.parse(String(init!.body));
        expect(body.challengeId).toBe("ch-1");
        expect(body.username).toBe("alice");
        return new Response(
          JSON.stringify({
            credential: {
              credentialId: "cred",
              userHandle: "uh",
              label: "key",
              transports: [],
              counter: 0,
              backupEligible: false,
              backupState: false,
              authenticatorData: "ad",
            },
          }),
          { status: 200 },
        );
      }
      throw new Error("unexpected " + String(url));
    });

    const rawId = new Uint8Array([42]);
    const fakeCreds = {
      create: vi.fn(async () =>
        fakeCredential(rawId, {
          clientDataJSON: new Uint8Array([0]).buffer as ArrayBuffer,
          attestationObject: new Uint8Array([0]).buffer as ArrayBuffer,
          getTransports: () => ["internal"],
        } as unknown as AuthenticatorResponse),
      ),
      get: vi.fn(),
    } as unknown as CredentialsContainer;

    const client = new PkAuthCeremonyClient(
      { apiBase: "https://x", fetch: fetchImpl as unknown as typeof fetch },
      { credentials: fakeCreds },
    );
    const result = await client.register({ username: "alice", label: "key" });
    expect(result.credential.credentialId).toBe("cred");
    expect(fakeCreds.create).toHaveBeenCalledOnce();
  });
});
