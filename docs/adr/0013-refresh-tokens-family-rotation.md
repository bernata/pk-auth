# 13. Rotating refresh tokens with family-based replay detection

Date: 2026-05-16

## Status

Accepted.

## Context

Through 1.0, pk-auth issued stateless access JWTs and stopped there. Real
consumers — motif at `/home/wolpert/projects/motif` is the canonical example
— hit the same wall: short-lived access tokens (15 minutes for web, longer
for CLI) need a refresh primitive so the bearer doesn't re-authenticate
every cycle. Without one in the library, every consumer rolls their own
table, their own atomicity story, and their own replay defense. Several
roll versions with subtle races that a malicious bearer can exploit.

The hard parts are:

1. **Replay detection.** A leaked refresh token used after the legitimate
   client has already rotated must be detectable. The detection has to be
   provably atomic — a select-then-update sequence races against the legit
   client and produces undefined behaviour.
2. **Response on replay.** Once detected, the entire session has to be
   killed (both the attacker and the legit client must re-authenticate).
   The cost is one re-auth for the user; the alternative is a leaked
   session that survives the legit client's rotation.
3. **Atomic rotation.** Mark-parent-used and insert-successor must commit
   together. A non-atomic sequence lets a concurrent rotator scorch the
   family between mark and insert, leaving a fresh successor un-revoked
   inside an otherwise-dead family.

Motif solved this with a family model: every rotation chain shares a
`family_id` (the root token's `refresh_id`). Each rotation produces a child
in the same family with a link to the parent. Detection is a single
conditional `UPDATE`; response is a family-wide revoke. The same shape
generalises cleanly to pk-auth's other backends (DynamoDB via
`TransactWriteItems`, in-memory via a `ConcurrentHashMap.compute` block).

## Decision

Ship a new `pk-auth-refresh-tokens` module with:

```java
public final class RefreshTokenService {
  RefreshTokenPair issue(UserHandle, String audience, Optional<String> deviceId);
  RotateResult     rotate(String presentedWireToken);   // sealed sum
  void             revokeFamily(String familyId, RevokeReason reason);
  int              revokeAllForUser(UserHandle, RevokeReason reason);
  List<RefreshTokenSummary> listForUser(UserHandle);
}
```

**Wire format.** `"{refreshId}.{secret}"` where both halves are base64url
(no padding). `refreshId` is 16 random bytes (22 chars); `secret` is 32
random bytes (43 chars). The on-the-wire string is opaque to clients —
they never need to parse it.

**Hash-at-rest.** `SHA-256(secret)` is persisted, the raw secret is not.
Single-shot, no salt — acceptable because the input is 256 bits from
`SecureRandom` and the hash is never exposed.

**Hash-before-mark-used.** The service hashes the presented secret and
compares against the stored row hash *before* invoking the atomic
mark-used primitive. A presented refresh-id with the wrong secret returns
`Unknown`, never `Replayed`, and never sets `used_at` on the legitimate
row. This is an operational invariant; the parity test
`wrongSecretReturnsUnknownAndDoesNotBurnLegitToken` enforces it.

**Atomic mark-and-insert via the SPI.** The `RefreshTokenRepository` SPI
exposes `rotateAtomically(parentRefreshId, now, successor)` returning
`true` iff the parent was fresh AND the successor was inserted, atomic on
every backend:

- **JDBI:** `jdbi.inTransaction(...)` wrapping a single conditional
  `UPDATE` on the parent and an `INSERT` for the successor.
- **DynamoDB:** `TransactWriteItems` with a `ConditionExpression` on the
  parent's primary item (used_at + revoked_at attribute_not_exists,
  expires_at > :now) and conditional puts for the successor's primary and
  index items.
- **In-memory testkit:** `ConcurrentHashMap.compute(parentId, ...)` block
  that checks the freshness predicate and inserts the successor under
  `putIfAbsent` before returning the updated parent.

**Family scorch outside the rotation.** When `rotateAtomically` returns
`false` (lost the race, or parent flipped used/revoked between read and
write), the service calls `revokeFamily(familyId, ROTATION_REPLAY)`
outside the failed-rotation scope. That revoke always commits, even if
the rotation transaction itself rolled back — losing rotators always
scorch.

**Non-negotiable concurrent rotation race test.** A `CountDownLatch`-gated
test launches 8 threads all rotating the same root token simultaneously.
Exactly one thread returns `Success`; the other 7 return `Replayed`; the
entire family (root + the winner's successor) ends up revoked. This test
must pass against:

- The in-memory testkit (drives the `compute` path)
- JDBI against a real Postgres container (drives the JDBI transaction
  path)
- DynamoDB against DynamoDB Local (drives `TransactWriteItems`)

The shared `RefreshTokenScenarios` class lives in `pk-auth-testkit` so
all three backends drive the same nine scenarios.

**Sealed result type.** `RotateResult` has five variants:

- `Success(pair, claimsForAccessIssue)` — winner's response
- `Replayed(familyId, userHandle)` — losers' response after family scorch
- `Expired()` — past-due token (no family revocation; expired is not a
  replay signal)
- `Unknown()` — refresh-id not found, malformed wire token, or wrong
  secret
- `Revoked(reason)` — family was previously scorched for any reason

Adapters map `Success` → 200; the four failures → 401 with a typed
`detail` body. The browser SDK's `PkAuthClient.refresh(wireToken)`
returns a typed `RefreshResult` sum, never throws on 401.

**Composition.** The service does not call `PkAuthJwtIssuer` itself.
`RotateResult.Success` carries a `RotatedClaims` projection (userHandle +
audience + deviceId) the caller hands to the issuer if it wants to mint a
fresh access JWT. Adapters provide a small `RefreshHandler` helper that
ties the two together; hosts that want their own access-token shape
compose differently.

**User-deletion fan-out integration.** A `RefreshTokenServiceDeletionListener`
implements `UserDeletionListener` and calls `service.revokeAllForUser(handle,
USER_DELETED)`. Each adapter auto-registers it via the same DI mechanism
that wires the other listeners (Spring auto-collection, Dagger
`@ElementsIntoSet`, Micronaut `Collection<UserDeletionListener>`).

## Consequences

- **Pro**: Server-revocable session model end-to-end. Consumers like
  motif can delete their `RefreshTokenManager` and the supporting code
  paths.
- **Pro**: The family-scorch + atomic-rotate combo provably detects
  replay regardless of which side (attacker or legit client) presents
  first. The concurrent race test is the proof at the persistence
  boundary.
- **Pro**: Composability preserved — `RefreshTokenService` and
  `PkAuthJwtIssuer` are independent. Hosts assemble them as they like.
- **Pro**: Operator-rare admin actions (logout, "log out everywhere",
  user delete) all reduce to a single SPI call.
- **Con**: One database table (Postgres `refresh_tokens` / DynamoDB
  `RT#/RTU#/RTF#` items). Operators need a daily cleanup cron — documented
  in `docs/operator-guide.md`.
- **Con**: The DynamoDB three-item layout (primary + user-index +
  family-index) writes 4 items per rotation (parent update + 3 successor
  items). For high-rotation workloads this is the main cost driver — but
  refresh rotations are by definition infrequent (once per access-token
  lifetime) so the total throughput is small.
- **Con**: A false-positive replay (legit client's next refresh hits an
  already-revoked family for any reason) requires re-authentication. The
  user sees a single login prompt; the cost is one ceremony. Acceptable.

## Open follow-ups

- A device-binding field on `RefreshTokenRecord` is reserved (the SPI
  carries `Optional<String> deviceId`) but neither the issuer nor the
  refresh handler currently populates it from a typed device-id concept.
  When pk-auth adds a `DeviceRegistry` SPI (post-1.1) the field becomes
  load-bearing for per-device revocation.
- A `RefreshTtlPolicy` based on JWT audience parallels the access-token
  `TokenTtlPolicy` (ADR 0014). They're independent; hosts can serve
  web=15m-access/14d-refresh and cli=1h-access/90d-refresh from one
  configuration block.
- The refresh-token row currently doesn't store the original auth method
  (passkey vs backup-code vs magic-link) — the new access token minted
  on rotation always carries `AuthMethod.REFRESH`. Hosts that need the
  original provenance must look it up via their own session table.
