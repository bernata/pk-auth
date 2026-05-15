'use strict';

var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/base64url.ts
var base64url_exports = {};
__export(base64url_exports, {
  decode: () => decode,
  decodeToArrayBuffer: () => decodeToArrayBuffer,
  encode: () => encode
});
function encode(input) {
  const bytes = toUint8Array(input);
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decode(input) {
  const pad = "=".repeat((4 - input.length % 4) % 4);
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function decodeToArrayBuffer(input) {
  const bytes = decode(input);
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

// src/http.ts
var PkAuthHttpError = class extends Error {
  status;
  body;
  constructor(status, body) {
    super(`HTTP ${status}: ${body}`);
    this.name = "PkAuthHttpError";
    this.status = status;
    this.body = body;
  }
};
async function request(options, method, path, body, authenticated) {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const base = options.apiBase.endsWith("/") ? options.apiBase.slice(0, -1) : options.apiBase;
  const url = `${base}${path}`;
  const headers = { accept: "application/json" };
  let payload;
  if (body !== void 0) {
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
  const init = { method, headers };
  if (payload !== void 0) init.body = payload;
  const response = await fetchImpl(url, init);
  const text = await response.text();
  if (!response.ok) {
    throw new PkAuthHttpError(response.status, text);
  }
  if (!text.length) {
    return void 0;
  }
  return JSON.parse(text);
}

// src/ceremonies.ts
var PATHS = {
  startReg: "/auth/passkeys/registration/start",
  finishReg: "/auth/passkeys/registration/finish",
  startAuth: "/auth/passkeys/authentication/start",
  finishAuth: "/auth/passkeys/authentication/finish"
};
var PkAuthCeremonyClient = class {
  client;
  paths;
  credentials;
  constructor(client, options = {}) {
    this.client = client;
    this.paths = { ...PATHS, ...options.paths };
    this.credentials = options.credentials;
  }
  /**
   * Runs the full registration ceremony: server-start → `navigator.credentials.create` →
   * server-finish. Returns the finish payload (registered credential metadata).
   */
  async register(params) {
    const start = await this.startRegistration({
      username: params.username,
      displayName: params.displayName ?? params.username,
      label: params.label ?? null,
      challenge: null
    });
    const created = await this.createCredential(start.publicKey);
    return this.finishRegistration({
      challengeId: start.challengeId,
      username: params.username,
      label: params.label ?? null,
      response: encodeRegistrationResponse(created)
    });
  }
  /**
   * Runs the full sign-in ceremony: server-start → `navigator.credentials.get` →
   * server-finish. Returns the JWT (consumer is responsible for storage).
   */
  async authenticate(params = {}) {
    const start = await this.startAuthentication({
      username: params.username ?? null,
      challenge: null
    });
    const got = await this.getCredential(start.publicKey, params.conditional ?? false);
    return this.finishAuthentication({
      challengeId: start.challengeId,
      response: encodeAuthenticationResponse(got)
    });
  }
  startRegistration(body) {
    return request(this.client, "POST", this.paths.startReg, body, false);
  }
  finishRegistration(body) {
    return request(this.client, "POST", this.paths.finishReg, body, false);
  }
  startAuthentication(body) {
    return request(this.client, "POST", this.paths.startAuth, body, false);
  }
  finishAuthentication(body) {
    return request(this.client, "POST", this.paths.finishAuth, body, false);
  }
  get credentialsImpl() {
    if (this.credentials) return this.credentials;
    if (typeof navigator === "undefined" || !navigator.credentials) {
      throw new Error("pk-auth: navigator.credentials is not available in this environment");
    }
    return navigator.credentials;
  }
  async createCredential(options) {
    const publicKey = decodeCreationOptions(options);
    const credential = await this.credentialsImpl.create({ publicKey });
    if (!credential) {
      throw new Error("pk-auth: credential creation was cancelled");
    }
    return credential;
  }
  async getCredential(options, conditional) {
    const publicKey = decodeRequestOptions(options);
    const request2 = { publicKey };
    if (conditional) {
      request2.mediation = "conditional";
    }
    const credential = await this.credentialsImpl.get(request2);
    if (!credential) {
      throw new Error("pk-auth: authentication was cancelled");
    }
    return credential;
  }
};
function decodeCreationOptions(options) {
  return {
    rp: options.rp,
    user: {
      id: decodeToArrayBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    challenge: decodeToArrayBuffer(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    attestation: options.attestation,
    authenticatorSelection: options.authenticatorSelection,
    excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({
      id: decodeToArrayBuffer(c.id),
      type: c.type,
      transports: c.transports
    }))
  };
}
function decodeRequestOptions(options) {
  return {
    challenge: decodeToArrayBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    userVerification: options.userVerification,
    allowCredentials: (options.allowCredentials ?? []).map((c) => ({
      id: decodeToArrayBuffer(c.id),
      type: c.type,
      transports: c.transports
    }))
  };
}
function encodeRegistrationResponse(credential) {
  const response = credential.response;
  const transports = typeof response.getTransports === "function" ? response.getTransports() : [];
  return {
    id: encode(credential.rawId),
    rawId: encode(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      attestationObject: encode(response.attestationObject),
      transports
    }
  };
}
function encodeAuthenticationResponse(credential) {
  const response = credential.response;
  return {
    id: encode(credential.rawId),
    rawId: encode(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null
    }
  };
}

// src/admin.ts
var PATHS2 = {
  account: "/auth/admin/account",
  credentials: "/auth/admin/credentials",
  credentialById: (id) => `/auth/admin/credentials/${encodeURIComponent(id)}`,
  backupRegen: "/auth/admin/backup-codes/regenerate",
  backupCount: "/auth/admin/backup-codes/count",
  emailStart: "/auth/admin/email/start-verification",
  emailComplete: "/auth/admin/email/complete-verification",
  phoneStart: "/auth/admin/phone/start-verification",
  phoneComplete: "/auth/admin/phone/complete-verification"
};
var PkAuthAdminClient = class {
  client;
  constructor(client) {
    if (!client.getToken) {
      throw new Error("pk-auth: admin client requires `getToken` in ClientOptions");
    }
    this.client = client;
  }
  getAccount() {
    return request(this.client, "GET", PATHS2.account, void 0, true);
  }
  listCredentials() {
    return request(this.client, "GET", PATHS2.credentials, void 0, true);
  }
  renameCredential(credentialId, label) {
    return request(this.client, "PATCH", PATHS2.credentialById(credentialId), { label }, true);
  }
  removeCredential(credentialId) {
    return request(this.client, "DELETE", PATHS2.credentialById(credentialId), void 0, true);
  }
  regenerateBackupCodes() {
    return request(this.client, "POST", PATHS2.backupRegen, "", true);
  }
  remainingBackupCodes() {
    return request(this.client, "GET", PATHS2.backupCount, void 0, true);
  }
  startEmailVerification(email) {
    return request(this.client, "POST", PATHS2.emailStart, { email }, true);
  }
  completeEmailVerification(token) {
    return request(this.client, "POST", PATHS2.emailComplete, { token }, true);
  }
  startPhoneVerification(phone) {
    return request(this.client, "POST", PATHS2.phoneStart, { phone }, true);
  }
  completePhoneVerification(phone, code) {
    return request(this.client, "POST", PATHS2.phoneComplete, { phone, code }, true);
  }
};

// src/index.ts
var PkAuthClient = class {
  ceremonies;
  admin;
  constructor(options, ceremonyOptions = {}) {
    this.ceremonies = new PkAuthCeremonyClient(options, ceremonyOptions);
    this.admin = new PkAuthAdminClient(options);
  }
};

exports.PkAuthAdminClient = PkAuthAdminClient;
exports.PkAuthCeremonyClient = PkAuthCeremonyClient;
exports.PkAuthClient = PkAuthClient;
exports.PkAuthHttpError = PkAuthHttpError;
exports.base64url = base64url_exports;
exports.decodeCreationOptions = decodeCreationOptions;
exports.decodeRequestOptions = decodeRequestOptions;
exports.encodeAuthenticationResponse = encodeAuthenticationResponse;
exports.encodeRegistrationResponse = encodeRegistrationResponse;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map