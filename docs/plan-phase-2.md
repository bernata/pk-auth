# Phase 2 — `pk-auth-core` ceremony implementation

Per brief §10, Phase 2 implements `DefaultPasskeyAuthenticationService` using WebAuthn4J's `WebAuthnManager`. No exceptions cross the service boundary for ceremony-flow failures — every failure mode becomes a variant of the corresponding `*Result` sealed interface. The `ChallengeStore` is wired with atomic single-use semantics.

**Acceptance:** Service is unit-testable with mocks. No framework dependencies. ≥80% line coverage on `pk-auth-core` still holds.

## Task list (in execution order)

1. **`StartRegistrationResponse` / `StartAuthenticationResponse` wrapper types** — see clarifying question 1. If we go with option A, this is the first concrete API change.
2. **`internal/` ceremony helpers** — package-private:
   - `ChallengeGenerator` — 32 random bytes from `SecureRandom`; ChallengeId derivation per question 2.
   - `ClientDataJsonParser` — minimal Jackson parse of `clientDataJSON` to extract `type`, `challenge`, `origin` *before* full WebAuthn4J validation, so we can resolve the `ChallengeRecord` from the store.
   - `WebAuthn4JConverters` — translate between our DTOs and WebAuthn4J's parsed input types (`RegistrationData`, `AuthenticationData`, etc.).
3. **`DefaultPasskeyAuthenticationService`** in `internal/` (constructor-public via a factory in `ceremony/`):
   - `startRegistration`: resolve user handle via `UserLookup.createOrGetUserHandle`, generate challenge, persist `ChallengeRecord(REGISTRATION)` with `CeremonyConfig.challengeTtl`, build `PublicKeyCredentialCreationOptionsJson` honoring the request's UV/RK overrides falling back to `CeremonyConfig`.
   - `finishRegistration`: parse `clientDataJSON` → derive ChallengeId → `takeOnce` → build WebAuthn4J `RegistrationRequest`/`RegistrationParameters` → `webAuthnManager.parse(...)` then `.validate(...)` → catch every WebAuthn4J validation/exception type and map to the right `RegistrationResult` variant → on success, build a `CredentialRecord` and an `AuthenticatorData`, persist via `CredentialRepository.save`, return `RegistrationResult.Success`.
   - `startAuthentication`: if username present, look up handle, list its credentials for `allowCredentials`; if absent (usernameless flow), leave `allowCredentials` empty. Generate challenge, persist `ChallengeRecord(ASSERTION)`.
   - `finishAuthentication`: derive ChallengeId, takeOnce, look up credential by `rawId`, build WebAuthn4J `AuthenticationRequest`/`AuthenticationParameters`, validate, map exceptions, on success update the repo's sign count + `lastUsedAt` and return `AssertionResult.Success`. Counter-regression policy honored from `CeremonyConfig`.
4. **`PasskeyAuthenticationServices` factory** in `ceremony/` — single `create(...)` static method returning the configured default impl. Keeps `internal/` truly internal.
5. **Exception → result mapping table** — exhaustive coverage of every WebAuthn4J validation exception type. Documented inline.
6. **Metrics wiring** — counters: `pkauth.registration.outcome{result=...}`, `pkauth.assertion.outcome{result=...}`; timers: `pkauth.registration.duration`, `pkauth.assertion.duration`. Brief §8.
7. **Structured logging** — SLF4J at INFO for outcomes (with `eventId`, `userHandleB64Url`, `credentialIdSha256Hex8`, `outcome`, `latencyMs`); DEBUG for parsed flags. Brief §7 "No raw credential public keys or clientDataJSON in logs. Ever."
8. **Unit tests with mocks** — Mockito on every SPI. Cover:
   - Happy paths for both ceremonies.
   - Each `*Result` failure variant (exception mapping branches).
   - Challenge missing / expired / cross-ceremony-purpose.
   - Counter regression in both REJECT and WARN modes.
   - Origin mismatch (the OriginValidator says no).
   - User verification required but not asserted.
   - Sign-count update on success.
   - Metrics counters fire with the right tags.
   - `Metrics.noop()` swallows correctly when no MeterRegistry is wired.
9. **Verify** — `./gradlew clean build test` green; coverage gate still passes; check that no new exception types leak out of the service in the failing-path tests.

## Clarifying questions

1. **How does the client learn the `ChallengeId`?** Phase 1 has `FinishRegistrationRequest.challengeId` but `startRegistration` returns only `PublicKeyCredentialCreationOptionsJson` (no place for the id). Three options:

   - **A. Wrap the response.** Introduce `StartRegistrationResponse(ChallengeId challengeId, PublicKeyCredentialCreationOptionsJson publicKey)` (and the equivalent for authentication). The wire format mirrors the WebAuthn JSON Spec convention of nesting options under `publicKey`. Adds two record types and changes the service-interface return types. Cleanest from an API standpoint. **Recommended.**
   - **B. Derive ChallengeId from the challenge bytes.** Define `ChallengeId == base64url(challenge bytes)`. The server doesn't return ChallengeId at all; at finish time it parses `clientDataJSON`, extracts the challenge, computes the id, and looks it up. `FinishRegistrationRequest.challengeId` becomes redundant — either remove it or use it purely as a cross-check.
   - **C. Custom extension.** Smuggle ChallengeId into the `extensions` map of the options JSON. Non-standard; browser will ignore it; the demo TS SDK has to know to pull it out.

2. **Counter-regression `WARN` mode behavior.** Brief §7: "configurable to `warn` for sites that primarily expect synced (counter-0) passkeys." When the policy is `WARN`, do we (i) accept the assertion as success with a log warning and *don't* update the stored count, (ii) accept and *do* update, or (iii) accept only when both counters are zero (synced credential signature) and treat any other regression as REJECT? I lean toward (i) — accept, log, don't update — but this is security-sensitive. Confirm?

3. **`internal/` exposure.** `DefaultPasskeyAuthenticationService` is the only thing the brief positively names. The factory `PasskeyAuthenticationServices.create(...)` lives in `ceremony/`. Should the impl class be `package-private` (consumed only via the factory) or public-but-internal-module-package (so test sub-classes can extend it)? I lean toward public-class-in-internal-package — same effective scope from JPMS export rules, no friction for unit tests. Confirm?

I'll wait for answers (or "go with your defaults / recommended") before writing code.
