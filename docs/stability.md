# pk-auth Stability and Versioning

## Current status: pre-1.0

pk-auth is **pre-1.0**. All SPI signatures, configuration keys, and wire-format
contracts may change between minor version bumps (e.g. 0.4 → 0.5) without a
deprecation period. We will document breaking changes in release notes, but we
do not guarantee a migration window.

If you are adopting pk-auth today, pin to an exact version in your build file
and review the changelog before upgrading:

```kotlin
// build.gradle.kts
implementation("com.example:pk-auth-core:0.x.y")  // pin exact version pre-1.0
```

## Post-1.0 policy (planned)

Once pk-auth reaches 1.0, the project will follow [Semantic Versioning](https://semver.org/):

| Change type | Version bump |
|---|---|
| Backwards-compatible additions to SPIs or REST wire format | MINOR (1.x) |
| Breaking change to any SPI method signature, removal of a method, or breaking wire-format change | MAJOR (2.0, 3.0, …) |
| Bug fixes that do not alter the public API | PATCH (1.x.y) |

Configuration key renames or removals are treated as breaking changes and require a
MAJOR bump post-1.0.

## SPI surfaces

The following interfaces are the **extension points** that host applications implement.
These are the surfaces most likely to evolve before 1.0:

| SPI interface | Module | Purpose |
|---|---|---|
| `CredentialRepository` | `pk-auth-core` | Store and retrieve WebAuthn credential records |
| `UserLookup` | `pk-auth-core` | Resolve a username to an internal user handle |
| `ChallengeStore` | `pk-auth-core` | Issue and atomically consume ceremony challenges |
| `BackupCodeRepository` | `pk-auth-backup-codes` | Store and verify Argon2id-hashed backup codes |
| `OtpRepository` | `pk-auth-otp` | Store and verify time-limited OTP codes |
| `EmailSender` | `pk-auth-magic-link` | Dispatch magic-link emails |
| `SmsSender` | `pk-auth-otp` | Dispatch phone OTP messages |
| `RateLimiter` | `pk-auth-core` | Host-implemented rate limiting hook |
| `RevocationCheck` | `pk-auth-jwt` | Determine whether a valid JWT has been revoked |

### `@apiNote experimental` convention

Every SPI method above is implicitly experimental until 1.0. A future pass will
annotate each method with `@apiNote experimental` in its Javadoc to make this
machine-readable. Until that annotation appears, treat every SPI method as subject
to change between minor releases.

## Configuration keys

All configuration lives under the `pkauth.*` prefix. Keys are considered experimental
pre-1.0. Post-1.0, renamed keys will be kept as deprecated aliases for at least one
minor release before removal.

## Wire format (REST + TypeScript SDK)

The REST API shape (`/auth/**` routes) and the TypeScript SDK (`@pk-auth/passkeys-browser`)
are versioned together. Breaking REST changes require a MAJOR bump post-1.0, the same as
SPI changes.
