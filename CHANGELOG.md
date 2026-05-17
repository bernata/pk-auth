# Changelog

All notable changes to pk-auth are recorded here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The 0.x line is treated as a single pre-stable development series — see
`docs/stability.md` and the early ADRs for context. This changelog starts at the
1.0.0 stabilisation cut; for 0.x history consult `git log` against the relevant
tags.

## [Unreleased]

### Added

- `TokenTtlPolicy` SPI in `pk-auth-jwt` for per-audience JWT access-token TTL
  dispatch. Multi-client deployments (e.g. web vs cli vs mobile) can now
  configure different token lifetimes per audience without writing a custom
  issuer. Static factories `TokenTtlPolicy.fixed(default, overrides)` and
  `TokenTtlPolicy.single(ttl)` cover the common cases; implementations can also
  declare their `knownAudiences()` so the validator accepts the expanded
  audience set automatically. See ADR 0014.
- `JwtClaims` gains an optional `audience` field. When the issuer is called
  with a claims object whose `audience` is null, the JWT's `aud` claim falls
  back to `JwtConfig.defaultAudience()`. New convenience factory
  `JwtClaims.forPasskey(userHandle, credentialId, audience, amr)` etc. mirror
  the existing audience-less factories.
- `AccessTokenStore` SPI in `pk-auth-jwt` for stateful (server-revocable) access
  tokens. `PkAuthJwtIssuer` calls `record` on every issue; `PkAuthJwtValidator`
  calls `exists` on every validate. The default `AccessTokenStore.noop()` keeps
  stateless behaviour; hosts wire a real store (JDBI, DynamoDB) to opt in. See
  ADR 0015.
- `pk-auth-persistence-jdbi`: `JdbiAccessTokenStore` backed by the new
  `access_tokens` table (Flyway V8).
- `pk-auth-persistence-dynamodb`: `DynamoDbAccessTokenStore` using two items
  per JTI (primary jti-keyed item + user-indexed pointer item) with DynamoDB
  native TTL on the `ttl` attribute for asynchronous expiry cleanup.
- `pk-auth-testkit`: `InMemoryAccessTokenStore` + `AccessTokenStoreScenarios`
  parity-test class driven from in-memory / JDBI / DynamoDB integration tests.
- `UserDeletionService` and `UserDeletionListener` SPI in
  `pk-auth-core` (`com.codeheadsystems.pkauth.lifecycle`). Single fan-out
  point that runs every registered listener for a user, with idempotent +
  best-effort semantics and structured `pkauth.user.deletion` logging. See
  ADR 0016. The library ships listeners for credentials, backup codes, OTPs,
  and access tokens; each adapter wires them automatically.
- `CredentialRepository.deleteByUserHandle(UserHandle)` and
  `OtpRepository.deleteByUserHandle(UserHandle)` SPI methods for the fan-out.
  Implemented in all three persistence variants.

### Changed

- **Breaking.** `JwtConfig.tokenTtl: Duration` replaced by
  `JwtConfig.ttlPolicy: TokenTtlPolicy`. Pre-1.1 code that constructed
  `JwtConfig` directly must wrap the existing TTL in `TokenTtlPolicy.single(ttl)`.
  The `JwtConfig.defaults(issuer, audience)` factory still works as before and
  produces a single-TTL policy.
- **Breaking.** `JwtConfig.audience` renamed to `JwtConfig.defaultAudience`.
  The accessor moves from `config.audience()` to `config.defaultAudience()`.
  Semantic note: the validator now accepts any audience listed in
  `defaultAudience ∪ ttlPolicy.knownAudiences()`, which matters when running
  multiple client audiences through a single validator.
- **Breaking (adapters).** `PkAuthProperties.Jwt` (Spring),
  `PkAuthConfig.Jwt` (Dropwizard), and `PkAuthConfiguration.Jwt` (Micronaut)
  each gain a `ttlsByAudience: Map<String, Duration>` field and rename their
  single-TTL field; see each adapter's javadoc for the bound property name.
- **Breaking (SPI).** `CredentialRepository` and `OtpRepository` gain a
  `deleteByUserHandle(UserHandle) -> int` method. All shipped implementations
  (in-memory, JDBI, DynamoDB) updated. Downstream host-supplied
  implementations must add it; the natural impl is a single bulk-delete
  statement keyed on the user-handle column.
- `PkAuthJwtIssuer` and `PkAuthJwtValidator` gain new constructors that accept
  an `AccessTokenStore`. The legacy three-arg constructors remain and default
  to `AccessTokenStore.noop()`.
- Flyway schema version bumped to V8. `PkAuthJdbiSchema.CURRENT_SCHEMA_VERSION`
  is now `"8"`.

## [1.0.0] — 2026-05 (stabilisation cut)

First stable release. Captures the surface produced by the 0.x development
series; see `git log` for the full history.

[Unreleased]: https://github.com/codeheadsystems/pk-auth/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/codeheadsystems/pk-auth/releases/tag/v1.0.0
