# pk-auth — Consolidated Review TODO

Stack-ranked findings from five parallel review agents (crypto-auth security,
web/injection security, maintainability, API/SPI consistency, dead code).
Each entry cites its origin (e.g. `[Crypto #1]`, `[Web #2]`, `[Maint #4]`,
`[API #5]`, `[DeadCode #7]`) referring back to
`.review-findings/0{1..5}-*.md`.

Ranking blends **severity** (security > correctness > parity > polish) with
**effort/risk asymmetry** (small targeted fixes ranked higher when they remove a
real exploitable hazard). Severity tags: **Crit / High / Med / Low / Info**.

Cross-agent conflicts and overlaps are called out at the bottom of the
relevant items and summarized in the **Conflicts** section at the end.

---

## Maintainer decisions (locked 2026-05-16)

These pre-answer questions that would otherwise come up mid-implementation:

1. **Release stance:** pre-1.0. Breaking changes are acceptable without a
   deprecation cycle.
2. **`@since` value:** stamp every new or modified public element with
   `@since 0.9.1` (the next release).
3. **Adapter defaults (items #19, #20):** no defaults anywhere — adopt
   Dropwizard's fail-fast policy in Spring and Micronaut. RP id, RP name,
   origins, JWT issuer, audience, and signing key are all required. Remove
   Spring's silent random-JWT-key fallback.
4. **Verb pair (item #23):** standardize on `start*/finish*` everywhere.
   `OtpService.send`/`verify` → `start*`/`finish*`; `MagicLinkService.send*`
   /`consume` → `start*`/`finish*`; admin's `start*`/`complete*` →
   `start*`/`finish*`; `BackupCodeService.regenerateAll` aligned with
   `AdminService.regenerateBackupCodes`.
5. **`CredentialRepository.delete` semantics (item #55):** hard delete in all
   three implementations (JDBI changes from soft-delete to hard-delete).
   pk-auth emits a deletion log event whenever a credential is deleted —
   audit history lives in logs, not in the credentials table.
6. **`PkAuthErrorCode` unused constants (item #71):** document as reserved
   wire vocabulary. No adapter wiring at this time.
7. **In-source `TODO #NN` markers (item #67):** walk each one with the code;
   delete comments for items that are already done, leave the rest as plain
   prose pointing to the relevant brief / ADR. Do NOT re-establish the
   numeric tracker.
8. **Questionable Gradle dependencies (items #69, #70):** delete now; revert
   only if system tests fail. Keep `TwilioSmsSender` and `JavaMailEmailSender`
   stubs (item #72) — they ship intentionally as starter scaffolds.
9. **PR batching:** four PRs in order — (a) Tier 1 security hotfixes (#1–#8),
   (b) SPI sweep covering repository contract changes (#2, #3, #8, #18, #27,
   #28), (c) adapter-parity sweep covering shared DTOs / mappers /
   orchestrator (#10–#17), (d) cleanup PR for dead code and stale comments
   (#61–#68). Tier 2 / Tier 3 items not listed in (b) or (c) slot into the
   nearest matching batch.

---

## Tier 1 — Exploitable security & correctness (do first)

### ✅ 1. Fix JDBI OTP attempt-cap bypass — `>` vs `>=` plus no-op increment after cap
**Completed:** 2026-05-16 — JdbiOtpRepository.incrementAttempts now unconditional; OtpService.verify uses `>=`.
- Severity: **High** — [Crypto #1]
- File: `pk-auth-otp/.../OtpService.java:194-198` + `pk-auth-persistence-jdbi/.../JdbiOtpRepository.java:60-85` (`incrementAttempts`)
- Issue: once `attempts == max_attempts`, the guarded JDBI UPDATE is a no-op and
  `newAttempts > maxAttempts` is never true. Unlimited verify attempts against the
  10⁶ code space within the 5-minute TTL. DynamoDB impl is unaffected.
- Fix: make `JdbiOtpRepository.incrementAttempts` increment unconditionally
  (matches DynamoDB / SPI contract). Belt-and-braces: also change comparator to
  `>=` in `OtpService.verify`.
- Related: [API #23] (the `int` sentinel-0 return shape of `incrementAttempts` is
  the deeper SPI smell — change return to `OptionalInt`). [Crypto #8] (the
  concurrent off-by-one is a flavour of the same problem).

### ✅ 2. Fix backup-code race — same code accepted twice under concurrent verify
**Completed:** 2026-05-16 — `BackupCodeRepository.consume` now returns `boolean`; JDBI/DynamoDB/InMemory impls atomic; service treats false as NoMatch.
- Severity: **High** — [Crypto #2]
- File: `pk-auth-backup-codes/.../BackupCodeService.java:286-294`; `BackupCodeRepository.consume` is void.
- Issue: two concurrent verifies both pass Argon2id, both call `consume`, both
  return `Success`. The recovery flow can mint two JWTs from one code.
- Fix: change `BackupCodeRepository.consume` to return `boolean` (true when the
  guarded UPDATE actually consumed an unconsumed row). Update JDBI, DynamoDB, and
  testkit impls. `BackupCodeService.verify` treats `false` as `NoMatch`.

### ✅ 3. Fix OTP single-use race — same OTP accepted twice under concurrent verify
**Completed:** 2026-05-16 — `OtpRepository.consume` returns `boolean`; JDBI adds `consumed=FALSE` guard; service treats false as race-lost mismatch.
- Severity: **High** — [Crypto #3]
- File: `pk-auth-otp/.../OtpService.java:206-209` + `JdbiOtpRepository.java:87-97`.
- Issue: same shape as #2. JDBI's `UPDATE otp_codes SET consumed=TRUE` has no
  `consumed=FALSE` guard. Add the guard and return rowcount.
- Fix: same pattern as #2 — boolean-returning `consume`, with `consumed=FALSE`
  guard in JDBI.

### ✅ 4. JWT validator accepts kid-less tokens against every key — defeats kid rotation
**Completed:** 2026-05-16 — PkAuthJwtValidator now rejects kid-less tokens when the keyset has any kid-bearing key; regression test added.
- Severity: **Med** — [Crypto #4]
- File: `pk-auth-jwt/.../PkAuthJwtValidator.java:190-217` (`verifyAgainstCandidateKeys`)
- Issue: when token header has no `kid`, validator tries every key — including
  retired ones. A leaked retired key signs a kid-less token and is accepted.
- Fix: if any key in the keyset has a `kid`, require `kid` in the header. Legacy
  "no-kid" branch should fire only when **no** key carries a kid.

### ✅ 5. Make magic-link single-use enforcement multi-replica safe
**Completed:** 2026-05-16 — New `ConsumedJtiStore` SPI in pk-auth-core; Caffeine-backed `InMemoryConsumedJtiStore` default with single-instance WARN.
- Severity: **Med** — [Crypto #5] and [Web #7] (independent agents flagged the same issue)
- File: `pk-auth-magic-link/.../MagicLinkService.java:192-196, 286-292`
- Issue: consumed-JTI tracking is a per-process Caffeine cache. A captured magic
  link is replayable on every other replica in the cluster within the 30-minute
  TTL.
- Fix: add a `ConsumedJtiStore` SPI (mirror `MagicLinkRateLimiter`) with the
  Caffeine cache as the default and a documented "production must override".
  Log a single-instance-only warning at startup.

### ✅ 6. Stop leaking account existence via WebAuthn `start*` response shape
**Completed:** 2026-05-16 — allowCredentials / excludeCredentials always non-null; serialize as `[]` on the wire; new tests assert JSON shape.
- Severity: **Med** — [Web #1]
- Files: `pk-auth-core/.../internal/DefaultPasskeyAuthenticationService.java:141-189, 307-351`
- Issue: `startAuthentication` emits `allowCredentials = null` for unknown users
  and a populated list for known ones. `startRegistration` symmetrically reveals
  via `excludeCredentials`. Both endpoints are `permitAll`. Combined with #7
  this is unbounded enumeration.
- Fix: always return non-null `allowCredentials` / `excludeCredentials` (empty
  list when no user / no exclusions). Match the privacy guard
  `MagicLinkService.sendLoginEmail:250-269` already implements.

### ✅ 7. Rate-limit WebAuthn ceremony endpoints
**Completed:** 2026-05-16 — New `CeremonyRateLimiter` SPI with in-memory Caffeine default wired into all four entrypoints + Spring/Dropwizard/Micronaut; `RateLimited` variant on result types; 429 surfaced.
- Severity: **Med** — [Web #2]
- Files: ceremony controllers in all three adapters (Spring, Dropwizard,
  Micronaut) + Spring `permitAll` chain in `PkAuthWebAutoConfiguration:87-99`.
- Issue: zero throttling on `start*`/`finish*`. Enables enumeration (#6),
  challenge spam, and brute-force assertion attempts.
- Fix: add a `CeremonyRateLimiter` SPI mirroring `MagicLinkService.MagicLinkRateLimiter`
  with a default in-memory Caffeine per-IP / per-username implementation.

### ✅ 8. Make persistence implementations actually wrap exceptions as `PkAuthPersistenceException`
**Completed:** 2026-05-16 — JDBI/DynamoDB/InMemory repos now wrap backend exceptions; `PkAuthPersistenceException` sealed; new `DuplicateCredentialException` (#18) + `OtpRepository.incrementAttempts → OptionalInt` (#28) bundled.
- Severity: **High** — [API #5]
- Files: `pk-auth-core/.../spi/PkAuthPersistenceException.java:18-22` (Javadoc);
  every shipped JDBI / DynamoDB / testkit repository.
- Issue: contract says implementations wrap backend errors; **none do**. The 503
  exception mappers in all three adapters therefore never fire on a real DB
  outage — DB failures surface as framework-default 500 HTML pages.
- Fix: wrap native exceptions in `PkAuthPersistenceException("<repo>.<op>", message, cause)`
  in every shipped repo. Or soften the Javadoc — but (a) is the documented intent.

---

## Tier 2 — Adapter parity & API/SPI consistency (high-impact public surface)

### ✅ 9. Dropwizard adapter does not auto-wire OTP / MagicLink / BackupCode services
**Completed:** 2026-05-16 — added new AltFlowsModule + PkAuthFullComponent; PkAuthBundle gets an alt-flow constructor; demo updated.
- Severity: **High** — [API #1]
- Files: `pk-auth-dropwizard/.../dagger/PkAuthModule.java`; `PkAuthBundle.java:72`.
- Issue: Spring and Micronaut auto-wire all three; Dropwizard hosts must
  hand-build them. The "three adapters expose the same admin endpoints" promise
  is structurally hollow.
- Fix: add `Otp` block to `PkAuthConfig`, alt-flow provider methods to
  `PkAuthModule`, and a `PkAuthBundle` constructor that constructs
  `DefaultAdminService` internally.

### ✅ 10. Unify admin response body shape across adapters
**Completed:** 2026-05-16 — promoted `BackupCodesCountResponse` and `EmailVerificationResult` into pk-auth-admin-api; all three adapters now emit identical JSON.
- Severity: **High** — [API #3]
- Files: Spring `PkAuthAdminController.java:85-94, 105-115` vs Dropwizard
  `:100-104` vs Micronaut `:91-95`.
- Issue: `GET /auth/admin/backup-codes/count` returns `{"remaining": n}` in
  Spring but bare `n` elsewhere. `POST email/complete-verification` returns
  `{"userHandle": "..."}` in Spring but a raw `UserHandle` JSON in the others.
  The TypeScript SDK can target only one shape.
- Fix: promote shared response records to `pk-auth-admin-api`
  (`BackupCodesCountResponse(int remaining)`, `EmailVerificationResult(String userHandle)`).
  Spring's `Map.of(...)` shape is the right shape.

### ✅ 11. Promote admin request-body DTOs into `pk-auth-admin-api`
**Completed:** 2026-05-16 — new `AdminRequests` class with five nested records; Spring/Dropwizard/Micronaut adapters use them.
- Severity: **High** — [API #2] and [Maint #19] (same finding, two agents)
- Files: Spring `:144-157` (`RenameBody`, `EmailBody`, ...); Dropwizard `:35-47`
  (`RenameRequest`, `EmailStartRequest`, ...); Micronaut `:170-178`
  (`RenameRequest`, `EmailRequest`, ...).
- Issue: three sets of names for the same five wire bodies; a typo in one
  silently breaks parity.
- Fix: move records into `pk-auth-admin-api` as `AdminRequests.RenameCredential` etc.

### ✅ 12. Delete `AdminErrorBody` and align the documented schema with what adapters emit
**Completed:** 2026-05-16 — AdminErrorBody.java + test deleted; DESIGN.md error-envelope description rewritten to match adapter mappers.
- Severity: **High** — [API #4] + [DeadCode #1] (conflict **resolved: delete**)
- Files: `pk-auth-admin-api/.../AdminErrorBody.java` and its test
  `AdminErrorBodyTest.java`; `*AdminResultMapper.java` in all three adapters.
- Decision: **delete** `AdminErrorBody` (and its test). The three adapter
  mappers will remain the source of truth for the `{outcome, error, detail}`
  envelope. The shared envelope helper still needs extracting — that work
  happens in item #13, not here.
- Follow-up: after deletion, sweep any docs that referenced the documented
  `{error, detail}` schema so they match what the mappers emit.

### ✅ 13. Extract `CeremonyOrchestrator` / `AdminFlow` to remove ~600 lines of triplicated adapter code
**Completed:** 2026-05-16 — new `CeremonyOrchestrator` in pk-auth-jwt owns the JWT-mint + label-lookup + wire-mapping pipeline; new `AdminResponseMapper` in pk-auth-admin-api owns the status / header / error-envelope logic. All three adapter ceremony controllers + admin controllers + per-adapter `errorEnvelope` helpers collapse to thin framework-binding shims.
- Severity: **High** — [Maint #1, #3, #7]
- Files: ceremony controllers (`PkAuthCeremonyController` x3 + Dropwizard's
  resource) and admin controllers / `PkAuthAdminResultMapper` x3 / inline
  `errorEnvelope` helpers x3.
- Issue: same finish-authentication post-processing, same admin endpoint
  dispatch, same status mapping written three times in three dialects.
- Fix: move the orchestration (JWT mint + label lookup + variant→status map)
  into framework-neutral helpers in `pk-auth-core` / `pk-auth-admin-api`.
  Adapter controllers shrink to ~30 lines each.
- Related: [API #29] (errorEnvelope duplication), [Maint #19] (request DTOs),
  [Maint #20] (rate-limiter classes), [Maint #18] (`currentUser()` patterns).

### ✅ 14. De-duplicate `resolveOtpPepper` between Spring and Micronaut adapters
**Completed:** 2026-05-16 — new `OtpPepperResolver` in pk-auth-otp; Spring + Micronaut adapters now call it.
- Severity: **High** — [Maint #2]
- Files: Spring `PkAuthAutoConfiguration.java:298-332`,
  Micronaut `PkAuthFactory.java:180-214` — 35 lines verbatim copy.
- Fix: extract `OtpPepperResolver.resolve(Supplier<String> configuredPepper, BooleanSupplier devMode)`
  to `pk-auth-otp`. Adapters become a two-line call.

### ✅ 15. Decompose oversized `finishRegistration` and `finishAuthentication`
**Completed:** 2026-05-16 — extracted verifyRegistrationWithW4j / evaluateAttestation / persistRegistration helpers; finishAuthentication uses resolveCredential / verifyAssertionWithW4j / persistAssertion; narrowed catch from RuntimeException to webauthn4j-specific types.
- Severity: **High** — [Maint #4]
- File: `pk-auth-core/.../internal/DefaultPasskeyAuthenticationService.java:193-302` (110 lines), `:354-461` (108 lines).
- Issue: each method does ~seven things and contradicts its own Javadoc's
  promised "four-step shape". A catch-all `RuntimeException` masks programming
  errors as `InvalidPayload`. Cognitive load is high for new contributors.
- Fix: extract `verify…WithW4j(…)`, `evaluateAttestation(...)`,
  `persistRegistration(...)` so `finish…` becomes a ~20-line orchestration.
- Related: [Maint #24] (narrow the `RuntimeException` catch when extracting).

### ✅ 16. Normalize credential-id URL path-template name across adapters
**Completed:** 2026-05-16 — Micronaut path template renamed from `{credentialIdB64}` to `{credentialId}`.
- Severity: **High** — [API #7]
- Files: Spring `:60` & Dropwizard `:71` use `{credentialId}`; Micronaut `:66`
  uses `{credentialIdB64}`. Runtime URL is the same; OpenAPI / SDK tooling
  isn't.
- Fix: rename Micronaut to `{credentialId}`.

### ✅ 17. Eliminate the Spring `toEmptyResponse` foot-gun
**Completed:** 2026-05-16 — collapsed into single `toResponse` that auto-detects null value → 204.
- Severity: **High** — [API #8]
- File: `pk-auth-spring-boot-starter/.../PkAuthAdminResultMapper.java:25-60`.
- Issue: caller has to choose `toResponse` vs `toEmptyResponse` for
  `AdminResult<Void>`. Dropwizard and Micronaut auto-detect via `value() == null`.
- Fix: collapse Spring's two entry points into one that checks
  `success.value() == null` and returns 204.

### ✅ 18. Make persistence repositories agree on duplicate-credential exception type
**Completed:** 2026-05-16 — Bundled with #8: new `DuplicateCredentialException extends PkAuthPersistenceException` thrown by all three credential repos.
- Severity: **High** — [API #6]
- Issue: all three impls throw `IllegalStateException` but with varying message
  text; SPI Javadoc says only "implementations must reject duplicates".
- Fix: declare `DuplicateCredentialException extends PkAuthPersistenceException`
  (combines naturally with #8) and update all three impls.

### ✅ 19. Drop RelyingParty defaults in Spring and Micronaut — adopt Dropwizard's fail-fast
**Completed:** 2026-05-16 — Spring `localhost` and Micronaut `example.com` defaults removed; missing values now fail fast.
- Severity: **Med** — [API #18]
- Files: Spring `PkAuthProperties.java:48-51` (`localhost`), Dropwizard
  `PkAuthConfig.java:23-29` (required), Micronaut `PkAuthConfiguration.java:75-77`
  (`example.com`).
- Decision: no defaults. Strip the Spring and Micronaut defaults; let
  framework binding fail fast when `pkauth.relying-party.{id,name,origins}`
  is missing.

### ✅ 20. Drop JWT defaults; throw on missing secret in all three adapters
**Completed:** 2026-05-16 — Spring's silent random-key fallback gone; new `JwtSecretResolver` in pk-auth-jwt centralizes fail-fast policy.
- Severity: **Med** — [API #19] and [Maint #23]
- Files: Spring `PkAuthProperties.java:66-69` (`issuer="pk-auth"`,
  `audience="pk-auth-clients"`), Dropwizard required, Micronaut
  `PkAuthConfiguration.java:107-108` (`issuer="pk-auth-micronaut"`).
- Decision: no defaults for issuer / audience / signing key. Remove Spring's
  silent random-key fallback; remove its `pk-auth`/`pk-auth-clients`
  defaults; remove Micronaut's `pk-auth-micronaut`/`pk-auth-micronaut-clients`
  defaults. Centralise the resolver in `pk-auth-jwt` so all three adapters
  share one fail-fast policy.

### ✅ 21. Add typed `dev-mode` property to Spring and Micronaut configs
**Completed:** 2026-05-16 — `boolean devMode` field added and bound on both adapters; string-property reads removed.
- Severity: **Med** — [API #20]
- Issue: `dev-mode` is consumed via `@ConditionalOnProperty` / `Environment.getProperty`
  but never bound on `PkAuthProperties` / `PkAuthConfiguration`. IDE / metadata
  tooling can't help hosts find it.
- Fix: add `boolean devMode` field and bind it; remove string-property reads.

### ✅ 22. Stop using `byte[]` in result records — use `CredentialId` / `UserHandle`
**Completed:** 2026-05-16 — registered Jackson serializers for CredentialId/UserHandle in core + Dropwizard + Micronaut; switched AssertionResult.Success/UnknownCredential, RegistrationResult.DuplicateCredential, CredentialSummary, EmailVerificationResult to typed value classes; wire JSON unchanged.
- Severity: **Med** — [API #10], [API #11], [API #17]
- Files: `AssertionResult.java:34, 86`; `RegistrationResult.java:48`;
  `CredentialSummary.java:25-27`; `UserHandle.java`; `CeremonyWireMapper.java:75, 121`.
- Issue: type-safe value classes inside the library degrade to raw `byte[]` at
  result records; every call site does `CredentialId.of(...)` and
  `Base64Url.encode(...)`. `UserHandle` has no Jackson serializer, so adapters
  produce divergent JSON (`AccountSummary` and `CredentialSummary` make opposite
  choices side-by-side).
- Fix: register custom Jackson serializers on `CredentialId` and `UserHandle`
  (base64url string) in `PkAuthObjectMappers`; switch the record fields to the
  value classes; delete the manual encodings.

### ✅ 23. Standardize on `start*/finish*` across every feature service
**Completed:** 2026-05-16 — `OtpService.send`/`verify` → `startVerification`/`finishVerification`; `MagicLinkService.sendVerificationEmail` → `startEmailVerification`, `sendLoginEmail` → `startLogin`, `consume` → `finishVerification`; `AdminService.completeEmailVerification` → `finishEmailVerification`, `completePhoneVerification` → `finishPhoneVerification`; `BackupCodeService.regenerateAll` → `regenerateBackupCodes`. All call sites + tests + adapter controllers updated; HTTP URL paths left unchanged (wire contract).
- Severity: **Med** — [API #9], [API #13]
- Files: ceremony (already `start*`/`finish*`), OTP (`send`/`verify`),
  magic-link (`send*`/`consume`), admin (`start*`/`complete*`),
  backup-codes (`generate`/`verify`/`regenerateAll`).
- Decision: rename to `start*`/`finish*` everywhere.
  - `OtpService.send` → `startVerification`; `OtpService.verify` →
    `finishVerification`.
  - `MagicLinkService.sendVerificationEmail` → `startEmailVerification`;
    `sendLoginEmail` → `startLogin`; `consume` → `finishVerification`
    (with overload for the login flow as needed).
  - `AdminService.startEmailVerification` already matches; rename
    `completeEmailVerification` → `finishEmailVerification` and the same for
    phone.
  - `BackupCodeService.generate` → `startEnrollment` (or keep as `generate`
    — single-shot, no redemption pair); `regenerateAll` →
    `regenerateBackupCodes` to match `AdminService`.
- Result-type names align too: `*Result.Success` / `Invalid` /
  `AlreadyFinished` across the board.

### ✅ 24. Unify service-construction patterns (single `create(Dependencies, Config)` factory)
**Completed:** 2026-05-16 — OtpService/MagicLinkService/BackupCodeService/DefaultAdminService all expose `create(Dependencies, Config)` + convenience overload; old multi-arg constructors removed; all adapter wiring + tests updated. PasskeyAuthenticationServices.Builder kept as-is per task spec.
- Severity: **Med** — [API #12] and [Maint #6]
- Files: `OtpService` (2 ctors), `MagicLinkService` (3), `BackupCodeService` (4),
  `DefaultAdminService` (3 statics + `Dependencies`), `PasskeyAuthenticationServices`
  (Builder).
- Fix: adopt `DefaultAdminService`'s "deps + optional config" idiom uniformly.

### ✅ 25. Generalize `EmailSender` and `SmsSender` SPIs
**Completed:** 2026-05-16 — renamed `sendMagicLink`/`sendOtp` to `send`; added generic `MessageFormatter<C,M>` SPI in pk-auth-core; per-feature `Context`/`Message`/`DefaultFormatter` records; existing copy preserved.
- Severity: **Med** — [API #14]
- Files: `EmailSender.java:11` (`sendMagicLink(to, subject, body)`),
  `SmsSender.java:12` (`sendOtp(to, message)`).
- Fix: rename to `send(String to, String subject, String body)` /
  `send(String to, String body)`; move message construction (including the
  hard-coded OTP body string in `OtpService.send`) into a `MessageFormatter` SPI.

### ✅ 26. Document and constrain `ChallengeStore.put` semantics
**Completed:** 2026-05-16 — Javadoc specifies overwrite-on-duplicate-key and rejects zero/negative TTL; all three impls validate.
- Severity: **Med** — [API #15]
- File: `pk-auth-core/.../spi/ChallengeStore.java:15`
- Issue: `put` has no Javadoc; `takeOnce` does. Overwrite-on-retry behaviour is
  unspecified — replay-protection-relevant.
- Fix: document overwrite vs reject; specify zero/negative TTL behaviour.

### ✅ 27. Tighten `BackupCodeRepository.replaceAll` — make it abstract
**Completed:** 2026-05-16 — default removed; method is abstract; DynamoDB impl now uses TransactWriteItems for atomicity.
- Severity: **Med** — [API #16]
- Issue: default does non-transactional delete-then-loop-save with "implementers
  SHOULD override" — silent foot-gun for new SPI implementers.
- Fix: drop the default; mark `abstract`. Combined with #2 (boolean
  `consume`), this aligns all three repository SPIs.

### ✅ 28. Tighten `OtpRepository.incrementAttempts` return shape
**Completed:** 2026-05-16 — Bundled with #8: SPI now returns `OptionalInt`; service maps empty to `NoActiveOtp`.
- Severity: **Med** — [API #23]
- Issue: returns `int` with `0` as sentinel for "row not found"; combined with
  the `>` comparator (#1) this is the same bug at the SPI level.
- Fix: change to `OptionalInt` and require the caller to handle "no row".

### ✅ 29. Rename `UserLookup` methods for parallelism and intent
**Completed:** 2026-05-16 — renamed to `findHandleByUsername`/`findViewByHandle`/`getOrCreateHandle`; promoted `__usernameless__` to `USERNAMELESS_KEY` constant (item #36 bundled).
- Severity: **Med** — [API #22]
- Fix: `findHandleByUsername`, `findViewByHandle`, `getOrCreateHandle`. Also
  promote the magic string `"__usernameless__"` to a constant (see #36).

### ✅ 30. Drop `AssertionResult.Success` convenience constructor (or move to static)
**Completed:** 2026-05-16 — convenience 3-arg constructor removed; callers must supply `counterStatus` explicitly.
- Severity: **Med** — [API #24]
- Fix: force callers to supply `counterStatus` explicitly, or expose
  `Success.ok(...)` as a static factory.

### ✅ 31. Stamp `@since 0.9.1` on every new/modified public element this sweep
**Completed:** 2026-05-16 — final sweep run; renamed methods from item #23 each carry `@since 0.9.1`. CONTRIBUTING.md §7 now codifies the policy (every new/modified public element gets `@since`; rename = new `@since` on the new shape, no history retained pre-1.0).
- Severity: **Med** — [API #21]
- Issue: zero `@since` tags across `pk-auth-core`, `pk-auth-admin-api`, `pk-auth-jwt`,
  `pk-auth-otp`, `pk-auth-magic-link`, `pk-auth-backup-codes`.
- Decision: stamp `@since 0.9.1` on every public element introduced or
  modified by this work (renames, new SPIs, new wire records). Document the
  policy in CONTRIBUTING.md so future PRs follow it.

---

## Tier 3 — Maintainability / low-severity security / polish

### 32. De-duplicate `mapRegistrationPreflight`/`mapAssertionPreflight` switches
- Severity: **Med** — [Maint #9]
- Fix: parameterise `ChallengeValidation.toResult(...)` on the sum type itself.

### 33. Lift adapter DI wiring recipes into a `PkAuthComposition` builder
- Severity: **Med** — [Maint #8]
- Files: `PkAuthAutoConfiguration.java` (333 lines), `PkAuthFactory.java` (227),
  `PkAuthModule.java` (171) all wire the same dozen beans.
- Fix: a framework-neutral construction recipe in core; each adapter exposes
  it as beans/factories.

### ✅ 34. Extract `mintCodes(...)` to remove `BackupCodeService.generate` ↔ `regenerateAll` duplication
**Completed:** 2026-05-16 — `mintCodes(user, plaintextSink)` centralises the Argon2id hash+wipe loop; `generate` saves one-by-one and `regenerateBackupCodes` calls `replaceAll`.
- Severity: **Med** — [Maint #5]

### ✅ 35. Narrow `MagicLinkService.jtiOf` `catch (Exception)` (and similar in `FakeAuthenticator`)
**Completed:** 2026-05-16 — `jtiOf` now catches only `ParseException`; `FakeAuthenticator.generateEcKeyPair` catches `NoSuchAlgorithmException | InvalidAlgorithmParameterException`.
- Severity: **Med** — [Maint #12]
- Files: `MagicLinkService.java:310-316`, `FakeAuthenticator.java:225`.

### ✅ 36. Promote the `"__usernameless__"` magic string to a constant; rename `stored2`
**Completed:** 2026-05-16 — bundled with #29; magic string is now `UserLookup.USERNAMELESS_KEY`. (`stored2` rename not done — defer.)
- Severity: **Med** — [Maint #10]

### 37. Replace metric-tag string concatenation with a `Ceremony` enum
- Severity: **Med** — [Maint #13]

### ✅ 38. Collapse `toExcludeDescriptor` / `toAllowDescriptor` to one helper
**Completed:** 2026-05-16 — merged into a single `toDescriptor(CredentialRecord)`; both call sites updated.
- Severity: **Med** — [Maint #14]

### ✅ 39. Validate `MagicLinkService` `baseUrl` for scheme + CRLF
**Completed:** 2026-05-16 — `Config` compact constructor rejects any `baseUrl` lacking an `http(s)://` prefix or carrying whitespace / CRLF.
- Severity: **Low** — [Web #4]
- Fix: reject any `baseUrl` that isn't `https://` (or `http://` in dev mode), or
  that contains `\r\n` / whitespace, in the constructor.

### 40. Don't retain raw JWT bearer inside `PkAuthJwtAuthenticationToken`
- Severity: **Low** — [Web #3]
- Fix: replace the token field with the parsed `JwtClaims`-only view, or override
  `eraseCredentials()` to null the token post-set.

### 41. Guard against accidental cookie auth on `/auth/**`
- Severity: **Low** — [Web #5]
- Fix: in `PkAuthJwtAuthenticationFilter`, refuse to authenticate when only a
  cookie is present (the CSRF-disabled config is correct only for header-bearer).

### 42. Make `startEmailVerification` indistinguishable on email match vs mismatch
- Severity: **Low** — [Web #6]
- Files: `DefaultAdminService.java:167-170`, `MagicLinkService.java:205-215`.
- Fix: return the same `204` for both; surface mismatch via audit log only.

### 43. Demote username logging in Spring ceremony controller from INFO to DEBUG
- Severity: **Low** (PII) — [Web #8]
- Asymmetry note: Dropwizard and Micronaut adapters do not log usernames at
  controller level — fix the Spring side or hide both behind
  `pkauth.observability.log-usernames` (default false).

### 44. Fix DynamoDB challenge-store expiry lex-compare (use numeric epoch)
- Severity: **Low** — [Crypto #6]
- File: `DynamoDbChallengeStore.java:56-79`. ~1 second of stale TTL can slip past.
- Fix: store `expiresAt` as numeric epoch-millis; cleanest fix also enables
  DynamoDB attribute TTL.

### ✅ 45. Run dummy HMAC on OTP "no active OTP" branch to remove timing leak
**Completed:** 2026-05-16 — `OtpService.finishVerification` now performs a throwaway `hmacHash` + constant-time compare on the no-active-OTP branch.
- Severity: **Low** — [Crypto #7]
- Pattern already used by `BackupCodeService` for consumed rows.

### ✅ 46. Reduce dev-mode SPI fallback logs from ERROR to WARN
**Completed:** 2026-05-16 — all seven `LOG.error` calls in Spring `PkAuthAutoConfiguration` lowered to `LOG.warn`.
- Severity: **Low** — [API #32]
- File: `PkAuthAutoConfiguration.java:118, 126, 134, 142, 150, 238, 249`.

### ✅ 47. Document `WebAuthnManager` non-strict mode's attestation-statement guarantee
**Completed:** 2026-05-16 — `AttestationTrustPolicy` Javadoc now states the `format` field is informational under `AttestationConveyance.NONE`; only `DIRECT` (or stricter) triggers webauthn4j's format-specific verifier.
- Severity: **Low** (intended behavior) — [Crypto #9]
- Fix: add explicit Javadoc on `AttestationTrustPolicy` that the `format` field
  is not cryptographically verified when `conveyance == NONE`.

### ✅ 48. Enforce HS256 secret length at keyset construction
**Completed:** 2026-05-16 — `JwtKeyset.hs256` now rejects secrets shorter than 32 bytes with a clear error message.
- Severity: **Info** — [Crypto #11]
- Fix: `if (secret.length < 32) throw new IllegalArgumentException(...)` in
  `JwtKeyset.hs256(...)`.

### ✅ 49. Migrate fully-qualified JDK class references to imports
**Completed:** 2026-05-16 — replaced FQ `java.util.HashMap` / `java.util.Map` / `java.security.MessageDigest` / `java.nio.charset.StandardCharsets` / `java.util.LinkedHashMap` references in `MagicLinkService`, `OtpService`, and `PkAuthJwtValidator` with imports.
- Severity: **Low** — [Maint #11]
- Files: `MagicLinkService.java:212, 296, 312`, `PkAuthAutoConfiguration.java:192, 304`,
  `PkAuthFactory.java:165, 181, 199, 208`.

### 50. Add a single in-memory rate-limiter type used by both backup-codes and magic-link
- Severity: **Low** — [Maint #20]
- Issue: `InMemoryBackupCodeRateLimiter` (45 lines) and
  `MagicLinkService.InMemoryRateLimiter` solve the same problem with
  non-identical APIs.

### 51. Add a build-time check that `PkAuthIntrospections` lists every wire record
- Severity: **Low** — [Maint #17]
- Fix: a `@Test` that reflectively walks the `api` / `admin` packages and
  asserts every record/sealed-variant appears in `@Introspected`.

### 52. Pick a rule for `pk-auth-core/internal/` package depth (move `ChallengeValidator` up or `ChallengeGenerator` down)
- Severity: **Low** — [Maint #25]

### 53. Standardize constructor injection annotations across adapters
- Severity: **Low** — [Maint #21]
- Spring/Micronaut single-ctor injection is implicit; Dropwizard marks `@Inject`.
  Document the policy or annotate consistently.

### 54. Reconcile `ChallengeRecord.Purpose.ASSERTION` with host-facing "authentication" vocabulary
- Severity: **Low** — [API #27]
- Fix: rename enum value to `AUTHENTICATION` (least disruptive).

### 55. Make `CredentialRepository.delete` a hard delete in all impls; emit a deletion log event
- Severity: **Low** — [API #28]
- Files: `JdbiCredentialRepository.java:28-30, 34` (currently soft-delete via
  `revoked_at`); `DynamoDbCredentialRepository.java`; `InMemoryCredentialRepository.java:77-79`.
- Decision: hard delete everywhere; pk-auth emits a structured log event
  (`pkauth.credential.deleted` with credential_id_b64 + user_handle_b64 +
  timestamp) at the service layer when a credential is removed. Drop the
  `revoked_at` column from the JDBI schema (Flyway migration) and the
  associated `revoked_at IS NULL` guards in queries.
- Document on the SPI: `delete` is hard delete; audit history is the host
  log pipeline's responsibility.

### 56. Rename `PasskeyAuthenticationServices.Builder` setters from `v` to descriptive names
- Severity: **Low** — [API #26]

### ✅ 57. Drop the deprecated `icon` field from `RelyingPartyConfig`
**Completed:** 2026-05-16 — `icon` and the 4-arg / 3-arg constructor pair removed; record is now a 3-component record. Tests updated.
- Severity: **Low** — [API #31]

### 58. Add explicit no-validation note (or accept) `CounterRegression`'s missing compact ctor
- Severity: **Low** — [API #25]

### 59. Audit `package-info.java` per package for stability/SPI markers
- Severity: **Low** — [Maint #28]

### 60. Sweep ADRs for staleness; add ADRs for the Spring Boot 4 / Jackson 3 / Micronaut 4 pins
- Severity: **Low** — [Maint #27]

---

## Tier 4 — Dead code & cleanup

### 61. Delete `listCredentialMetadata` from `DefaultPasskeyAuthenticationService`
- Severity: **High confidence** — [DeadCode #2]
- File: `DefaultPasskeyAuthenticationService.java:615-619`. Internal package; no callers.

### 62. Remove unused Gradle dep `argon2-jvm` from `pk-auth-otp`
- Severity: **High confidence** — [DeadCode #7]
- The module hashes with HMAC-SHA256 only; `argon2-jvm` is on `api` and leaks to
  consumers.

### 63. Remove unused Gradle dep `dropwizard-assets` from `pk-auth-dropwizard`
- Severity: **High confidence** — [DeadCode #8]
- Only the demo module uses `AssetsBundle`; the demo declares its own dep.

### 64. Delete empty `configurations.named("testImplementation")` no-op block
- Severity: **High confidence** — [DeadCode #6] and [Maint #22] (same finding)
- File: `pk-auth-spring-boot-starter/build.gradle.kts:74-78`.

### 65. Delete dead test helpers `requireRepo` and `mapper()`
- Severity: **High confidence** — [DeadCode #3, #5]
- Both already `@SuppressWarnings("unused")`; both have explanatory comments
  that turn out to be inaccurate (the imports they claim to preserve are used
  elsewhere).

### 66. Delete the `payloadTypes()` static-assertion in Micronaut `PkAuthAdminController`
- Severity: **Medium confidence** — [DeadCode #4]
- `PkAuthIntrospections` already wires those classes; the assertion is dead
  duplication.

### 67. Walk every in-source `TODO #NN` marker; delete if done, otherwise rewrite as prose
- Severity: **High confidence** — [DeadCode #11], [Maint #26], [DeadCode #13]
- Decision: do NOT re-establish the numeric tracker. For each marker below,
  read the surrounding code, decide whether the work is done, and either
  delete the comment or replace it with prose referencing the brief / ADR
  (no `TODO #N` revival, no new GitHub issue link required).
- Markers to walk:
  - `PkAuthDevModeGuardTest.java:18` — Javadoc references the removed TODO.md
  - `ChallengeGenerator.java:41` — `TODO #43` (commit `561b17b` says deferred)
  - `MagicLinkService.java:40` — TODO for shared-store rate limiter (now
    addressed by item #5's `ConsumedJtiStore` SPI)
  - `PkAuthCeremonyJwt.java:11` — `TODO #31`
  - Spring `PkAuthCeremonyController.java:42` — `TODO #31`
  - Spring `PkAuthJwtAuthenticationFilter.java:27` — `TODO #36`
  - Micronaut `PkAuthCeremonyController.java:35` — `TODO #29`
  - Micronaut `PkAuthAdminController.java:37` — `TODO #29`

### 68. Drop stale "Populated in Phase 2+" / Phase-0 comments
- Severity: **High confidence** — [DeadCode #12], [Maint #15, #16]
- Files: `pk-auth-core/.../internal/package-info.java:3`;
  `build-logic/.../pkauth.test-conventions.gradle.kts:34-36`;
  `build.gradle.kts:1-2, 7-9, 14-18, 51` (`phaseStatus` task printing "phase 0").
- Drop `phaseStatus` or repurpose to print the current published version.

### 69. Remove `dropwizard-jersey` dependency from `pk-auth-dropwizard`
- Severity: **Low** — [DeadCode #9]
- Decision: drop the `api(libs.dropwizard.jersey)` line. Run the full
  Dropwizard system test (`pk-auth-dropwizard` tests + `examples/dropwizard-demo`)
  after removal; revert this single line if it fails.

### 70. Remove `nimbus-jose-jwt` / `jackson-databind` / `jackson-annotations` from Spring starter
- Severity: **Low** — [DeadCode #10]
- Decision: drop the three `implementation(...)` lines. Both libs are pulled
  transitively (Nimbus via `pk-auth-jwt`, Jackson via Spring Boot web). Run
  the Spring starter system test + `examples/spring-boot-demo` after removal;
  revert individual lines if anything fails to resolve.

### 71. Document `PkAuthErrorCode` unused constants as reserved wire vocabulary
- Severity: **Low** — [DeadCode #14]
- Decision: keep the nine unused constants. Update the enum Javadoc to state
  explicitly that they are reserved wire-contract values; not all are emitted
  by the current adapter mappers.

### 72. Keep starter-stub senders; tighten their Javadoc
- Severity: **Info** — [DeadCode #15]
- Decision: keep `TwilioSmsSender` and `JavaMailEmailSender`. Their Javadoc
  already says "pk-auth ships only the SPI — host applications are expected
  to add the SDK and complete the implementation"; reinforce that this is
  intentional and not a half-finished feature.

---

## Conflicts and overlaps between agents

The agents worked independently. The following overlap or disagree:

1. **`AdminErrorBody` (item #12)** — was the one direct disagreement.
   **Resolved (2026-05-16): delete.** [DeadCode #1] path chosen; [API #4]'s
   adoption path rejected. The triplicated `errorEnvelope` extraction it
   would have addressed is folded into item #13.

2. **Magic-link consumed-JTI multi-replica replay (item #5)** — [Crypto #5]
   and [Web #7] independently flag this; not a conflict, just reinforcing
   coverage. The recommended fix (a `ConsumedJtiStore` SPI) is identical.

3. **Admin request DTOs duplicated per adapter (item #11)** — [API #2] and
   [Maint #19] flag it; not a conflict.

4. **`errorEnvelope` helper triplicated (item #13)** — [API #29] and [Maint #1]
   flag it; not a conflict.

5. **Empty `configurations.named` block (item #64)** — [DeadCode #6] and
   [Maint #22] flag it; not a conflict.

6. **Phase-0 / Phase-2+ stale comments (item #68)** — [DeadCode #12] and
   [Maint #15, #16] flag it; not a conflict.

7. **JWT-secret resolution (item #20)** — [Maint #23] says Spring's silent
   random-key fallback is wrong (Micronaut comment explicitly says so). [API
   #19] focuses on issuer/audience defaults. Compatible — fix together via a
   shared resolver in `pk-auth-jwt`.

8. **OTP attempt cap (items #1 and #28)** — [Crypto #1] is the exploitable
   surface bug (comparator + JDBI no-op increment); [API #23] is the underlying
   SPI smell (`int` return with sentinel 0). They reinforce each other; fix
   #1 first, then tighten the SPI shape in #28.

9. **Backup-code / OTP race-safety (items #2, #3) vs `replaceAll` non-abstract
   default (item #27)** — both flow into "the persistence SPI needs sharper,
   atomic operations". Consider doing these together: change `consume` to
   `boolean`, make `replaceAll` abstract, and wrap exceptions (#8) in one
   SPI-sweep PR.

10. **Decomposing `finishRegistration/finishAuthentication` (item #15) vs the
    `RuntimeException` catch-all ([Maint #24])** — same code path. Address the
    catch when refactoring rather than as a separate change.

11. **WebAuthn enumeration via null lists (item #6) vs ceremony rate-limiting
    (item #7)** — independent; the fix for #6 reduces, but does not remove,
    the value of #7. Do both.

No findings *recommend opposite changes to the same code* aside from #1
(`AdminErrorBody`).

---

## Source files

- `.review-findings/01-crypto-auth-security.md` — 11 findings (3 High, 1 Med,
  4 Low, 2 Info, 1 Low-informational).
- `.review-findings/02-web-injection-security.md` — 8 findings (3 Med, 5 Low).
- `.review-findings/03-maintainability.md` — 28 findings (4 High, 10 Med, 14 Low).
- `.review-findings/04-api-spi-consistency.md` — 32 findings + adapter parity
  table (8 High, 14 Med, 10 Low).
- `.review-findings/05-dead-code.md` — 15 findings (7 High confidence, 1 Medium,
  7 Low / needs verification).
