# `@pk-auth/passkeys-browser`

Zero-dependency TypeScript SDK for the pk-auth wire contract.
Consumed by every example app via a relative path — no npm publish step.

## API

```ts
import { PkAuthClient } from "@pk-auth/passkeys-browser";

const pk = new PkAuthClient({
  apiBase: "/",
  getToken: () => localStorage.getItem("pk-jwt"),
});

// Registration
await pk.ceremonies.register({ username: "alice", label: "MacBook" });

// Sign-in
const { token } = await pk.ceremonies.authenticate({ username: "alice" });
localStorage.setItem("pk-jwt", token);

// Admin (require a token)
await pk.admin.listCredentials();
await pk.admin.regenerateBackupCodes();
```

Two clients are exposed independently if a host only needs one half:

- `PkAuthCeremonyClient` — `startRegistration`, `register`, `startAuthentication`, `authenticate`.
- `PkAuthAdminClient` — `listCredentials`, `renameCredential`, `removeCredential`,
  `regenerateBackupCodes`, `remainingBackupCodes`, `startEmailVerification`,
  `completeEmailVerification`, `startPhoneVerification`, `completePhoneVerification`,
  `getAccount`.

### Conditional UI

```ts
await pk.ceremonies.authenticate({ conditional: true });
```

Wires `mediation: "conditional"` into the underlying `navigator.credentials.get` call,
so the browser can offer passkeys via autofill UI before the user clicks "Sign in."

### Adapter path differences

The default ceremony paths target Spring Boot / Micronaut (`/auth/passkeys/...`). The
Dropwizard adapter omits the `/passkeys/` segment; pass `paths` to override:

```ts
new PkAuthCeremonyClient(options, {
  paths: {
    startReg: "/auth/registration/start",
    finishReg: "/auth/registration/finish",
    startAuth: "/auth/authentication/start",
    finishAuth: "/auth/authentication/finish",
  },
});
```

## Build / test

```sh
npm install
npm test         # vitest, jsdom env
npm run build    # tsup → dist/index.{js,cjs,d.ts}
```

`dist/` is committed so the example apps work after a fresh clone without an npm
install step. Regenerate it with `npm run build` whenever `src/` changes.
