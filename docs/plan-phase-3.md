# Phase 3 — `pk-auth-testkit`

Per brief §6.8 and §10, Phase 3 ships the testkit: a `FakeAuthenticator` that mints valid WebAuthn ceremony responses in-process, in-memory implementations of every SPI, and canned fixtures. **Acceptance:** from the testkit module's own tests, drive a full registration → assertion ceremony against `DefaultPasskeyAuthenticationService` without a browser.

## Task list

1. **Wire the module** — `include("pk-auth-testkit")` in settings, `pk-auth-testkit/build.gradle.kts` applying `pkauth.library-conventions` + `pkauth.test-conventions` + `pkauth.publish-conventions`. Depend on `pk-auth-core` (`api`), webauthn4j-core (transitive via core), and the JUnit/AssertJ bundle for the testkit's own tests. Coverage gate at ≥80% (same as core).
2. **Package layout** — single package `com.codeheadsystems.pkauth.testkit`, module-info exporting it, `package-info.java` with `@NullMarked`.
3. **In-memory SPI impls**:
   - `InMemoryCredentialRepository` — thread-safe Map keyed by credentialId hex, plus a secondary index by user handle.
   - `InMemoryChallengeStore` — Caffeine cache with the configured TTL; `takeOnce` is `getIfPresent` + `invalidate`, atomic enough for tests.
   - `InMemoryUserLookup` — Map keyed by username, with `createOrGetUserHandle` minting a random UserHandle on miss.
4. **`PkAuthFixtures`** — canned `RelyingPartyConfig`, `CeremonyConfig`, sample `UserHandle`s, helper to build the testkit's bundled services.
5. **`FakeAuthenticator`** — the crown jewel:
   - Generates a fresh EC P-256 keypair per credential.
   - `createRegistrationResponse(StartRegistrationResponse)` — builds `clientDataJSON` (type `webauthn.create`, the challenge from options, the configured origin); builds `AuthenticatorData` (rpIdHash, flags including UP+UV+AT, signCount=0, AttestedCredentialData with our credential id + COSE key); wraps in an `AttestationObject` with `NoneAttestationStatement`; serializes via WebAuthn4J's `AttestationObjectConverter`; returns a `RegistrationResponseJson`.
   - `createAssertionResponse(StartAuthenticationResponse)` — picks the registered credential matching `allowCredentials` (or just the first one in usernameless mode); builds `clientDataJSON` (type `webauthn.get`); builds `AuthenticatorData` (signCount=1, then 2, …); signs `authData || sha256(clientDataJSON)` with the credential's private key (ES256); returns `AuthenticationResponseJson`.
   - Track signCount per credential so successive assertions bump it.
   - Builder lets tests override origin, rpId, AAGUID, UV/UP flag values, and force counter regression for negative-path tests.
6. **`InMemoryEverything`** — composes all in-memory SPIs + `FakeAuthenticator` + a `PasskeyAuthenticationService` built via the Phase 2 factory; one call gets you a fully wired test harness.
7. **End-to-end test** — `FullCeremonyTest`:
   - Set up `InMemoryEverything`.
   - Run startRegistration → fakeAuthenticator.createRegistrationResponse → finishRegistration; assert `RegistrationResult.Success`, credential persisted.
   - Run startAuthentication → fakeAuthenticator.createAssertionResponse → finishAuthentication; assert `AssertionResult.Success`, signCount bumped in the repo.
   - Loop a second assertion to confirm counter increment behavior.
   - Negative paths covered as separate tests: wrong origin (FakeAuthenticator misconfigured), counter regression in REJECT mode, unknown credential id.
8. **Verify** — `./gradlew clean build test` green; coverage gate intact on both modules.

## Open question — none

The brief is specific about what goes in this module. The only design choice is which library to lean on for the cryptography, and the answer is "WebAuthn4J's own types" — we already depend on it and reusing its `AttestationObjectConverter`, `EC2COSEKey`, and `AuthenticatorData` parsers/builders keeps the test code small and faithful.

Proceeding.
