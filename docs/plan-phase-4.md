# Phase 4 — `pk-auth-jwt`

Per brief §10 and §6.2, Phase 4 ships JWT issuance and validation as a separate module so adapter modules can pull in just the validator. **Acceptance:** round-trip issue → validate works; rejection on tampered signature, expired token, wrong audience, wrong issuer.

## Task list

1. **Wire the module** — `include("pk-auth-jwt")`, `pk-auth-jwt/build.gradle.kts` applying library + test + publish conventions. Depend on `pk-auth-core` (api), nimbus-jose-jwt (api), slf4j-api. Catalog entry for nimbus-jose-jwt (latest stable). Coverage gate ≥80% (treating it like core — substantive logic, not adapter glue).
2. **Public types under `com.codeheadsystems.pkauth.jwt`:**
   - `AuthMethod` enum: `PASSKEY`, `BACKUP_CODE`, `MAGIC_LINK`, with JSON values matching the brief's `passkey`/`backup-code`/`magic-link` spellings.
   - `JwtClaims` record carrying the standardized claims for an authenticated user: `userHandle: UserHandle`, `method: AuthMethod`, `credentialId: byte[]?` (only when `method == PASSKEY`), `amr: List<String>`, `additionalClaims: Map<String, Object>?`. Compact constructor validates that credentialId is present iff method is PASSKEY.
   - `JwtConfig` record: `issuer: String`, `audience: String`, `tokenTtl: Duration`, `notBeforeSkew: Duration`, `clockSkew: Duration` (validation tolerance). Defaults factory.
   - `JwtKeyset` — pluggable abstraction holding signing key + verification JWKSource. Built via factories: `hs256(byte[] secret)`, `es256(ECKey current, ECKey... rotated)`. Nimbus's `JWKSource<SecurityContext>` underneath. The "newest signs, all verify" rule from the brief lives here.
   - `PkAuthJwtIssuer` — `issue(JwtClaims) → String`. Constructor takes `JwtConfig`, `JwtKeyset`, `ClockProvider` (from core). Generates `jti` via UUID; sets `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, plus `pkauth.method`, `pkauth.cred` (when present), `pkauth.amr`.
   - `PkAuthJwtValidator` — `validate(String token) → JwtVerificationResult`. Verifies signature against any key in the keyset; checks `iss`, `aud`, `exp`, `nbf` (with `clockSkew` tolerance); reconstructs `JwtClaims`. Separate constructor seam from issuance — adapter modules typically only need the validator.
   - `JwtVerificationResult` — sealed interface: `Success(JwtClaims claims)`, `InvalidSignature`, `Expired(Instant exp)`, `NotYetValid(Instant nbf)`, `WrongIssuer(String expected, String actual)`, `WrongAudience(String expected, String actual)`, `Malformed(String detail)`, `MissingClaim(String name)`.
3. **Tests** — cover the acceptance bar plus key rotation:
   - Round-trip happy paths for HS256 and ES256.
   - Tampered signature (flip a byte in the JWT).
   - Expired (clock advanced past `exp`).
   - NotYetValid (clock before `nbf`).
   - Wrong issuer.
   - Wrong audience.
   - Malformed token (not three dot-separated parts).
   - Missing required claim (mutate the payload).
   - Key rotation: validator accepts tokens signed by an older key still present in the keyset; rejects tokens signed by a key removed from the set.
   - Method-credential invariant: `JwtClaims` rejects `credentialId` set without `method=PASSKEY` and vice versa.
   - `pkauth.amr` round-trips as a JSON array.
4. **Verify** — `./gradlew clean build test` green; coverage ≥80%.

No open questions — the brief is specific about the claim set and the keyset behavior. Proceeding with Nimbus JOSE+JWT.
