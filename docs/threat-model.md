# pk-auth Threat Model

Scope: the pk-auth library, its three host adapters, and the wire contract its TS
SDK consumes. This document is **not** a deployment review — host applications still
own their TLS, network ingress, secrets-management, and authorization layers.

## Trust boundaries

```
┌───────────────────┐    HTTPS     ┌──────────────────────────────┐    SPI    ┌────────────┐
│   Browser / SPA   │ ───────────► │  pk-auth-adapter (Spring/    │ ───────►  │ Persistence│
│  + authenticator  │  WebAuthn    │  Dropwizard/Micronaut)       │           │ (JDBI /    │
│  (TPM / Touch ID  │  ceremony +  │  + pk-auth-core              │           │  DynamoDB) │
│   / hardware key) │  admin JSON  │                              │           └────────────┘
└───────────────────┘              └──────────────┬───────────────┘
                                                  │ logs
                                                  ▼
                                            SIEM / metrics
```

Boundaries cross-checked in this model:
1. **Browser ↔ adapter** — untrusted client. WebAuthn assertions and admin calls.
2. **Adapter ↔ persistence** — trusted; assumes operator runs Postgres/DynamoDB on
   a private network.
3. **Adapter ↔ secrets / KMS** — trusted; assumes the host injects credentials at
   boot.

## STRIDE pass

### Spoofing

| Threat | Mitigation |
|---|---|
| Attacker forges a WebAuthn assertion | EC P-256/RSA signature verified against the registered public key via WebAuthn4J. Pre-existing public-key crypto is the only thing standing here; counter regression catches some clone scenarios. |
| Attacker forges a JWT | HS256 signature with ≥ 32-byte secret. JWT verification enforces issuer, audience, expiry. |
| Attacker spoofs the relying party | RP ID and origin are checked server-side on every `finish` call — config-driven allow-list (`pkauth.relying-party.origins`). Cross-origin attempts are rejected with `origin_mismatch`. |
| Attacker reuses a backup code | Backup codes are Argon2id-hashed, single-use, and atomically claimed inside the SPI (`atomic claim or fail`). |

### Tampering

| Threat | Mitigation |
|---|---|
| Tamper with the ceremony challenge | Challenges are server-issued, base64url, 32 random bytes, single-use via `ChallengeStore.takeOnce` (atomic). |
| Tamper with the credential record | Credential ID + public key + counter + AAGUID are the only fields trusted by the verifier; the label/UA are operator-supplied and never participate in signature checks. |
| Tamper with the JWT in transit | HTTPS protects on the wire; JWT integrity is the HS256 MAC. |

### Repudiation

| Threat | Mitigation |
|---|---|
| User claims they did not authenticate | Every `finish` call logs the (`userHandle`, `credentialId`, `clientDataJSON.origin`, signing counter) tuple. The user's authenticator is the only entity capable of producing the assertion, so the audit trail is non-repudiable assuming the authenticator was not lost. |
| Operator denies revoking a credential | Admin operations log the acting `userHandle` and the target `credentialId`. Logs are append-only by convention; ship them to an immutable store. |

### Information Disclosure

| Threat | Mitigation |
|---|---|
| Disclose a credential's public key | Public keys are public. Their disclosure leaks no authentication material. |
| Disclose backup codes | Backup codes are returned plaintext **exactly once** at regeneration time. The server only retains Argon2id hashes. |
| Disclose magic-link tokens | Magic-link tokens are random 32-byte values stored hashed; the plaintext only exists on the dispatcher path. Use a real email sender in production. |
| Disclose JWT secret via logs | The starter never logs `pkauth.jwt.secret`. Other secrets (Argon2 pepper, RP origins) are bound only via env vars; do not echo them in `--debug` traces. |
| Enumerate usernames | `/auth/passkeys/registration/start` returns the same shape for any username (a fresh user handle is created); `/auth/passkeys/authentication/start` does not leak existence — it returns an `allowCredentials` list that an unknown user would receive empty. Avoid mounting routes that surface user existence (e.g. "/users/exists"). |

### Denial of Service

| Threat | Mitigation |
|---|---|
| Flood challenges | Challenges expire in 5 minutes by default and are stored per-user — flooding inflates state proportional to attack volume but does not block legitimate users. Apply rate limiting at the host's WAF / API gateway. pk-auth does not ship a rate limiter. |
| Hash-burn via repeated OTP / backup-code attempts | Argon2id is intentionally CPU-heavy. The SPIs ship per-credential attempt counters; pair with a host-level rate limiter (`429 Retry-After`). |
| Exhaust DB connections | Connection pooling is the host's responsibility. Recommend HikariCP for JDBI, the AWS SDK's default for DynamoDB. |

### Elevation of Privilege

| Threat | Mitigation |
|---|---|
| Use a backup code to register a new passkey for someone else's account | Backup codes authenticate the holder; the admin API still requires a JWT for the *acting* user, and rename/delete enforce `actor == owner`. A backup code alone cannot register a passkey on a different account — only re-bootstrap the existing one. |
| Use a stolen JWT to act as another user | JWTs are stateless and bearer; mitigation lives at the transport layer (HTTPS) and TTL (default 1 hour). Do not extend TTL without offsetting it with explicit revocation. The library does not implement revocation lists in v0.x. |
| Delete every passkey to lock yourself in / out | `pkauth_admin.deleteCredential` enforces a "last-credential guard" returning 409 Conflict when a delete would leave zero credentials. Backup codes remain available as a recovery path. |
| Cross-tenant access | The library is single-tenant. Multi-tenant deployments need an outer key (e.g. `tenantId`) routed at the host. pk-auth does not provide one. |

## Known limitations (in scope but not solved)

- **Attestation policy**: ships as `none` by default. Hooks exist for MDS3 / metadata-service
  validation (`AttestationTrustPolicy`), but no MDS3 fetcher is bundled. Sites with FIDO
  attestation requirements must implement their own.
- **Counter regression**: rejected by default. Configurable to `warn` for sites that primarily
  expect counter-0 synced passkeys (Apple/Google ecosystems). Switching to `warn` weakens the
  clone-detection signal.
- **JWT revocation**: not in v0.x. Use short TTLs and accept the bound on session length.
- **Passkey export / migration**: not the library's concern. The user's authenticator owns the
  key material; pk-auth never sees it.

## Operator self-test

A deployment that survives the following spot checks is in reasonable shape:

1. Start the demo with the wrong `pkauth.relying-party.id`. Confirm Chrome rejects with
   "relying party not registrable."
2. Register a passkey, capture the assertion's signing counter, then replay an old assertion
   with a lower counter. Confirm the server rejects with `counter_regression`.
3. Delete the only credential on a user via the admin API. Confirm a 409.
4. Send the JWT in `Authorization: Bearer <token>` to a host-app endpoint that does not
   call `PkAuthJwtValidator`. Confirm the host's own filter chain rejects it (proves pk-auth
   isn't the only thing standing between the bearer and your code).
5. Restart the app and confirm Flyway / DynamoDB schema reconciles without manual intervention.
