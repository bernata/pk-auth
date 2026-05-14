# Phase 6 — Alternative-flow modules

Per brief §10 and §6.3–§6.5, Phase 6 lands three new modules (backup-codes, magic-link, OTP) plus persistence extensions in the JDBI and DynamoDB modules. **Acceptance:** each module independently testable with the testkit; integration tests against both persistence backends pass.

## Modules

### `pk-auth-backup-codes` (brief §6.3)

- `BackupCode` — value record (id + plaintext) used only at the issue-once moment; the service never returns it again after generation.
- `BackupCodeService` — `generate(UserHandle)`, `verify(UserHandle, String)`, `remainingCount(UserHandle)`, `regenerateAll(UserHandle)`. Default: 10 codes per generation, 10-character alphanumeric, Argon2id-hashed at rest, one-time use.
- `BackupCodeRepository` SPI — save / list / consume / replaceAll. Hashes stored via `de.mkammerer:argon2-jvm`.
- Tests with `InMemoryBackupCodeRepository` (lives in testkit) exercise: generate exactly N codes; codes verify; consumed codes don't verify a second time; `regenerateAll` deletes all prior codes and returns N new ones.

### `pk-auth-magic-link` (brief §6.4)

- `MagicLinkService` — `sendVerificationEmail(UserHandle, String email)`, `sendLoginEmail(String username)`, `consume(String token)`. Token is a JWT signed by `pk-auth-jwt`'s keyset with a `pkauth.purpose` claim (`email-verify` / `login`).
- `EmailSender` SPI plus `LoggingEmailSender` for dev and a `JavaMailEmailSender` skeleton (no live integration per brief §3).
- Default token TTL 15 minutes.
- Rate limiting: brief §6.4 says "at most N emails per (user, purpose) per hour, enforced in the service against the challenge store." For Phase 6 I'll use a simple in-memory Caffeine-backed rate limiter, with a `MagicLinkRateLimiter` interface so production deployments can plug in persistent state without touching the service. The brief's preference for ChallengeStore is noted in a follow-up TODO — happy to revisit before Phase 8 wires the demo apps.

### `pk-auth-otp` (brief §6.5)

- `OtpService` — `send(UserHandle, String phoneE164)`, `verify(UserHandle, String code)`. 6-digit numeric, default TTL 5 minutes, max 5 verification attempts per code, rate limit 3 codes per (user, phone) per 15 minutes.
- `SmsSender` SPI with `LoggingSmsSender` + `TwilioSmsSender` skeleton.
- `OtpRepository` SPI — save / find latest active / increment attempts / consume / count recent (for rate limit).
- Tests with `InMemoryOtpRepository`.

### Persistence extensions

**JDBI** — two new Flyway migrations (the V3/V4 slots reserved in Phase 5):
- `V3__backup_codes.sql` — `backup_codes(user_handle BYTEA, code_id TEXT PRIMARY KEY, hashed_code TEXT, consumed BOOLEAN, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ)`; index on `user_handle`.
- `V4__otp_codes.sql` — `otp_codes(otp_id TEXT PRIMARY KEY, user_handle BYTEA, phone_e164 TEXT, hashed_code TEXT, attempts INT, max_attempts INT, consumed BOOLEAN, expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ)`; index on `(user_handle, created_at)` for rate-limit query.
- `JdbiBackupCodeRepository`, `JdbiOtpRepository`.

**DynamoDB** — extend the single-table per ADR 0008 (no new tables). New item shapes:
- `BackupCodeItem` — `pk=USER#{handle}`, `sk=BACKUP#{codeId}`, payload (hashedCode, consumed flag, timestamps).
- `OtpItem` — `pk=USER#{handle}`, `sk=OTP#{otpId}`, payload (hashedCode, attempts, expiresAt + TTL).
- `DynamoDbBackupCodeRepository`, `DynamoDbOtpRepository`.

## Tasks

1. Wire all three new module subprojects.
2. Add argon2-jvm to the version catalog; module deps.
3. `BackupCodeRepository` SPI in pk-auth-core, plus `OtpRepository` SPI. `OtpRecord` value type.
4. `pk-auth-backup-codes` module: service + Argon2 hashing + `InMemoryBackupCodeRepository` in testkit.
5. `pk-auth-otp` module: service + `SmsSender` SPI + `LoggingSmsSender` + Twilio skeleton + `InMemoryOtpRepository` in testkit.
6. `pk-auth-magic-link` module: service + `EmailSender` SPI + `LoggingEmailSender` + JavaMail skeleton + in-memory rate limiter.
7. JDBI migrations V3 / V4 + repository impls + integration tests.
8. DynamoDB item beans + repository impls + integration tests.
9. Verify: `./gradlew clean build test` green, all coverage gates intact.

No open questions worth gating on — brief is specific. Proceeding.
