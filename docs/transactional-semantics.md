# pk-auth Transactional Semantics

## Overview

pk-auth does **not** require host SPI implementations to share a transactional
context. Each SPI method is called independently, and pk-auth makes no assumptions
about whether two SPI calls happen inside a shared database transaction.

This is a deliberate design choice that allows hosts to mix heterogeneous backends
(e.g. DynamoDB for `ChallengeStore` + Postgres for `CredentialRepository`) without
requiring a distributed transaction coordinator.

## Ceremony-finish ordering

At the end of a WebAuthn registration or authentication ceremony, pk-auth calls the
SPIs in this order:

1. `ChallengeStore.takeOnce(challengeId)` — the challenge is atomically consumed and
   can never be replayed, regardless of what happens next.
2. Signature / assertion verification (in-memory, no SPI).
3. `CredentialRepository.save(credential)` — the new or updated credential is persisted.

**If step 3 fails** (e.g. a transient database error), the challenge from step 1 is
already consumed. The ceremony cannot be retried with the same challenge. The user must
restart the ceremony from the beginning, which will cause pk-auth to issue a fresh
challenge.

## Why this is acceptable

Challenges are short-lived (default TTL: 5 minutes). A forced restart is a minor
inconvenience in the rare case of a transient failure, and it avoids significant
complexity:

- No `TransactionTemplate` SPI hook is needed.
- Heterogeneous backends (Dynamo + Postgres + Redis) can be mixed freely.
- The worst-case outcome of a failed save is that the user retries registration or
  authentication — not that an invalid credential is accepted.

## Hosts wanting stronger guarantees

Hosts that want atomicity across `ChallengeStore` and `CredentialRepository` can
implement both SPIs against the same backing store and wrap their calls in a shared
transaction. For example, a Postgres-only deployment can implement both SPIs using
JDBI and rely on a single database transaction.

pk-auth does not provide a `TransactionTemplate` SPI hook today. If your deployment
requires cross-SPI atomicity, both SPIs must target the same transactional resource.

## Other SPI pairs

The same non-transactional property applies wherever pk-auth calls multiple SPIs in
sequence:

| Sequence | Failure scenario | Recovery |
|---|---|---|
| `ChallengeStore.takeOnce` → `CredentialRepository.save` | Save fails; challenge is consumed. | User restarts ceremony (new challenge issued). |
| `BackupCodeRepository.claim` → JWT mint | Mint fails (e.g. secret missing). | Code is consumed; user contacts support or regenerates codes. |
| `OtpRepository.verify` → phone-verified flag write | Flag write fails. | OTP is consumed; user requests a new OTP and re-verifies. |

In every case, the "consume once" side of the operation succeeds before the downstream
write, and a failure leaves the user in a recoverable (if inconvenient) state.
