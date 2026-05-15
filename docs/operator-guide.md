# pk-auth Operator Guide

What an operator running pk-auth in production needs to know: secrets, persistence,
observability, rotation, and the most common ways a deployment goes wrong.

## 1. Required environment

pk-auth ships as a JVM library — Spring Boot 4, Dropwizard 4, or Micronaut 4
adapters all consume the same core. A typical production deployment needs:

- **JDK 21** (records, sealed types, virtual threads). Earlier JDKs will not compile.
- **Postgres 16+** (when using `pk-auth-persistence-jdbi`) — Flyway migrations run
  at startup, no manual schema work.
- **DynamoDB** (when using `pk-auth-persistence-dynamodb`) — single table, schema
  per item type. See ADR 0008 for the table layout.
- **At least one trusted dispatcher** for magic links + OTP if you enable those
  flows. The testkit's `LoggingEmailSender` / `LoggingSmsSender` log secrets to
  stdout; never use them in production.

## 2. Secrets

| Setting | Min length | Notes |
|---|---|---|
| `pkauth.jwt.secret` (HS256) | 32 bytes | Hard fail at boot if shorter. Rotate by issuing a fresh secret and tolerating a grace window (issue + verify in parallel — pk-auth itself does not rotate; the host shoulds run two issuers behind a load balancer until tokens expire). |
| `pkauth.relying-party.id` | n/a | The eTLD+1 (e.g. `example.com`, NOT `auth.example.com`). Cross-subdomain passkeys all bind to this. Once a credential is registered against an RP ID, it cannot be re-registered against a different one without a fresh enrollment. |
| `pkauth.relying-party.origins` | n/a | Strict allow-list of `https://` origins. WebAuthn rejects mismatches; expand the list as you add subdomains. |
| Argon2id pepper | n/a | Per-deployment salt-pepper for backup-code + OTP hashes. Treat as a long-lived secret; rotating it invalidates every existing hash. |

Recommended: stash secrets in a KMS/Secrets Manager and inject as environment
variables (`PKAUTH_JWT_SECRET`, `PKAUTH_ARGON2_PEPPER`). The adapters bind both.

## 3. Persistence migrations

### JDBI / Postgres

- Flyway resources live in `pk-auth-persistence-jdbi/src/main/resources/db/migration`.
- Migrations run automatically when the SPI is wired (see ADR 0003).
- `V1__pkauth_baseline.sql` creates `pkauth_credentials`, `pkauth_users`,
  `pkauth_backup_codes`, `pkauth_otp_codes`, and `pkauth_magic_links` with FK
  cascades on user delete.
- The unique key on credential ID is byte-array shaped — do **not** introduce a
  string-encoded column without a migration.

### DynamoDB

- Single physical table (see ADR 0008). Provision it before the app starts; the
  adapter does not create it.
- TTL attribute `expiresAt` is honored on `Challenge` / `OneTimePasscode` /
  `MagicLink` items — enable it on the table.
- Capacity-mode: on-demand is recommended for steady reads but bursty registration;
  provisioned only makes sense once you have a stable signing/verification baseline.

## 4. Observability

Every ceremony and admin operation emits structured logs at INFO. Suggested fields
to forward into your SIEM:

- `userHandle` (base64url), `challengeId`, `credentialId`
- `ceremony.phase` (`start` / `finish`) and `ceremony.step` (`registration` /
  `authentication`)
- `verification.kind` (`signature` / `originPolicy` / `rpIdPolicy` /
  `counterRegression` / `attestationPolicy`)
- `result` (`success` / `denied:<reason>`)

Counter regression and origin mismatch both surface as INFO log entries with a
distinct `result.denied.reason`. Alert on either — they are signals of credential
cloning or a misconfigured RP.

Recommended dashboards:

- p99 of `registration.finish` / `authentication.finish` (target < 200ms with
  Postgres on the same VPC).
- 4xx by reason on `/auth/passkeys/*` (origin mismatch is almost always config
  drift; counter regression is almost always an issue).
- Backup-code redemption and OTP attempt rates per user (the SPIs already
  rate-limit, but operator-side alerts catch credential-stuffing).

## 5. Rotation and re-enrollment

- **Passkey rotation**: users delete and re-add via `DELETE /auth/admin/credentials/{id}`
  and a fresh registration ceremony. The "last credential" guard returns 409 — that
  is intentional. Encourage users to add a second passkey before removing the first.
- **JWT secret rotation**: roll via the dual-issuer pattern in §2.
- **RP ID change**: a one-way migration. Every existing passkey is invalidated. Plan
  a re-enrollment campaign with backup codes / magic links as the bridge.

## 6. Failure modes worth practicing

| Symptom | Likely cause | First check |
|---|---|---|
| Browser shows "Relying party not registrable" | RP ID doesn't match the page's domain | The `pkauth.relying-party.id` config and the page's actual host |
| 4xx on `authentication.finish` with `counter_regression` | A counter wound back — either credential clone or counter-0 (synced) passkey crossing devices | Inspect the credential's `backupEligible` flag; if true, consider switching the policy to `warn` |
| `Challenge expired` 4xx | Five-minute default TTL elapsed | Often a slow user; do not extend the TTL — re-issue start |
| DynamoDB `ConditionalCheckFailedException` on `takeOnce` | Two clients tried to consume the same challenge | Expected; only one succeeds. If the rate is high, inspect for double-submit on the client |
| Spring Security 7 chain mounts before the pk-auth filter | Filter order regression | Verify `PkAuthSecurityConfig.pkAuthSecurityFilterChain` has the higher precedence in the host's chain |

## 7. Threat model

See `docs/threat-model.md` for the formal STRIDE pass.
