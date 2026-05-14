# Phase 7 — `pk-auth-admin-api`

Per brief §6.9 / §10, Phase 7 lands the framework-neutral admin service that the Spring / Dropwizard / Micronaut adapters will mount as HTTP endpoints. **Acceptance:** all admin operations covered by tests; the safety rules (especially "cannot delete the last credential without backup codes") enforced.

## Module shape

- Public package: `com.codeheadsystems.pkauth.admin`.
- Dependencies: `pk-auth-core` (api), `pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp` — all `api`. The brief explicitly forbids framework or HTTP deps here.
- Coverage gate ≥80% (admin-api is core-tier, not adapter glue).

## Types

- Sealed `AdminResult<T>` — `Success<T>(T value)`, `NotFound`, `Forbidden`, `ValidationFailed(String detail)`, `Conflict(String detail)`, `RateLimited(Duration retryAfter)`.
- DTO records:
  - `CredentialSummary(byte[] credentialId, String label, UUID aaguid, Set<String> transports, boolean backupEligible, boolean backupState, Instant createdAt, Instant lastUsedAt)`.
  - `AccountSummary(UserHandle, String username, String displayName, boolean emailVerified, boolean phoneVerified, int credentialCount, int remainingBackupCodes)`.
  - `BackupCodesGenerated(List<String> codes)` — one-time-view payload.
  - `OtpDispatchResult(String otpId)`.
  - `PhoneVerificationResult.Verified() / .Mismatch(int remaining) / .Expired() / .AttemptsExceeded()`.
- `AdminAuthorizer` SPI — `boolean canAct(UserHandle actor, UserHandle target)`. Default impl is subject-scoped: `actor.equals(target)`.

## Service

- `AdminService` interface — the brief's §6.9 method list, returning `AdminResult<T>` for everything.
- `DefaultAdminService` constructed via a builder that takes:
  - `CredentialRepository`, `UserLookup`, `BackupCodeService`, `MagicLinkService`, `OtpService`, `AdminAuthorizer`, `ClockProvider`, optional `safetyConfig` (last-credential guard on/off).

## Safety rules (brief §6.9)

1. `deleteCredential` returns `Conflict` if deletion would leave the user with zero credentials AND zero remaining backup codes. Configurable on/off via `AdminSafetyConfig.allowDeleteWithoutBackupCodes`.
2. `regenerateBackupCodes` is atomic: `BackupCodeService.regenerateAll` already does delete-then-issue.
3. Email / phone start operations propagate `RateLimited` from the magic-link / OTP services.
4. All endpoints except `completeEmailVerification` require a non-null actor and check `AdminAuthorizer.canAct(actor, target)`; on mismatch → `Forbidden`.

## Tests (InMemoryEverything)

- list / rename / delete credentials (happy path).
- delete last credential with no backup codes → `Conflict`.
- delete with backup codes present → `Success`.
- delete last credential when safety check disabled → `Success`.
- rename other user's credential → `Forbidden`.
- regenerate backup codes returns N plaintext, persists hashes, prior codes invalidated.
- remainingBackupCodes count.
- startEmailVerification dispatches and returns `Success`; rate-limit path returns `RateLimited`.
- completeEmailVerification with a real token from the magic-link service.
- startPhoneVerification + completePhoneVerification round-trip.
- getAccount returns the right shape with credential count + remaining backup codes.

## Tasks

1. Wire `pk-auth-admin-api` module.
2. DTOs, `AdminResult<T>`, `AdminAuthorizer`.
3. `AdminService` interface + `DefaultAdminService` + builder.
4. Tests against `InMemoryEverything` + in-memory backup-codes / magic-link / OTP services.
5. Verify (clean build test), commit.

No open questions — the brief is specific about method signatures, paths, and safety rules. The path-mounting concern lives in the Spring / Dropwizard / Micronaut adapters (Phase 8+), so this module ships only the Java surface.
