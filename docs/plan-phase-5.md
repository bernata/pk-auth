# Phase 5 — Persistence modules

Per brief §10 and §6.6 / §6.7, Phase 5 lands two persistence backends — JDBI + Postgres and AWS DynamoDB — each implementing `CredentialRepository`, `ChallengeStore`, and `UserLookup`. Both must pass the same Phase 3 ceremony test parameterized over the backend.

**Acceptance:** Same `FullCeremonyTest` shape (registration → assertion → repeat assertion) passes against both JDBI/Postgres and DynamoDB-local via parameterized tests. ADRs 0003, 0007, 0008 written. `./gradlew clean build test` green.

## Sub-plan 1 — `pk-auth-persistence-jdbi`

1. **Module wiring** — `include("pk-auth-persistence-jdbi")`, build.gradle.kts (library + test + publish conventions), dependencies on pk-auth-core (api), pk-auth-testkit (testImplementation, for the shared ceremony test fixtures), JDBI 3, Flyway, Postgres JDBC driver, HikariCP (connection pool), Testcontainers-Postgres (testImplementation). Coverage ≥70% (adapter tier).
2. **Flyway migrations** under `src/main/resources/db/migration/`:
   - `V1__credentials.sql` — `credentials` table with PK `credential_id BYTEA`, FK-free `user_handle BYTEA`, `public_key_cose BYTEA`, `sign_count BIGINT`, `label TEXT`, `aaguid UUID NULL`, `transports TEXT[]`, `backup_eligible BOOLEAN`, `backup_state BOOLEAN`, `created_at TIMESTAMPTZ`, `last_used_at TIMESTAMPTZ NULL`; index on `user_handle`.
   - `V2__challenges.sql` — `challenges` table with PK `id TEXT`, `challenge BYTEA NOT NULL`, `purpose TEXT NOT NULL CHECK (purpose IN ('REGISTRATION','ASSERTION'))`, `user_handle BYTEA NULL`, `expires_at TIMESTAMPTZ NOT NULL`; index on `expires_at` for sweep.
   - `V5__example_users.sql` — `users` table (`user_handle BYTEA PRIMARY KEY`, `username TEXT UNIQUE`, `display_name TEXT`, `email_verified BOOLEAN`, `phone_verified BOOLEAN`) for the demo apps and `JdbiUserLookup`. Numbered V5 to leave V3 / V4 reserved for the Phase 6 backup-code / OTP tables.
3. **Repository classes** under `com.codeheadsystems.pkauth.persistence.jdbi`:
   - `JdbiCredentialRepository` — implements `CredentialRepository`. RowMapper translates Postgres rows ↔ `CredentialRecord`. Uses `ON CONFLICT DO NOTHING` + `RETURNING` on save so duplicate inserts are detectable.
   - `JdbiChallengeStore` — implements `ChallengeStore`. `put` is an upsert. `takeOnce` is `DELETE … RETURNING …` so single-use semantics are atomic. Expired challenges are filtered in the query (`WHERE id = ? AND expires_at > NOW()`).
   - `JdbiUserLookup` — implements `UserLookup` against the `users` table. `createOrGetUserHandle` is an `INSERT … ON CONFLICT (username) DO NOTHING RETURNING user_handle` followed by a `SELECT` fallback.
   - `JdbiUserAdmin` (small helper) — `register(username, displayName)` for fixtures; the brief notes the users table is host-app data, so this lives outside the public SPI surface.
4. **`PkAuthJdbiSchema`** — a small entry point exposing `migrate(DataSource)` that runs the Flyway migrations; lets the demo apps and test fixtures bootstrap a fresh database.
5. **Test infra** — `PostgresContainerExtension` (JUnit 5) that starts a Testcontainers Postgres once per test class, runs Flyway, and exposes a `Jdbi` instance. The container's reuse mode is enabled so iteration is fast locally.
6. **Tests**:
   - Direct CRUD tests for each repo (save / find / list / update sign count / update label / delete; put / takeOnce; createOrGetUserHandle).
   - Concurrent `takeOnce` race test — two threads racing `takeOnce` on the same id; exactly one returns a non-empty Optional.
   - **Parameterized ceremony test** — extends `FullCeremonyTest` with the JDBI repos instead of the in-memory ones; same three test scenarios pass.
7. **ADR 0003** — `docs/adr/0003-jdbi-over-jpa.md` documenting why JDBI over JPA / Hibernate (brief §3 mandates this, §6.6 expands).

## Sub-plan 2 — `pk-auth-persistence-dynamodb`

1. **Module wiring** — `include("pk-auth-persistence-dynamodb")`, build.gradle.kts (library + test + publish), depend on pk-auth-core (api), pk-auth-testkit (testImplementation), AWS SDK v2 `dynamodb-enhanced` + `dynamodb`, Testcontainers (for dynamodb-local image). Coverage ≥70%.
2. **Single-table schema per brief §6.7.1** — `PkAuthCore` table with attributes `pk` (HASH, String), `sk` (RANGE, String), `entityType`, `ttl`, `gsi1pk`, `gsi1sk`, plus item-specific payload fields. GSI `gsi1-credential-by-id`. Separate `PkAuthUsers` table with its own GSI `gsi1-user-by-username`.
3. **`DynamoDbSchemaBootstrapper`** — idempotent helper that creates both tables (and the GSI) if missing. Used by local dev and the integration tests against dynamodb-local. Reads / writes the binary fields (challenge bytes, COSE public key) as **base64url strings**, per brief §6.7 ("simpler to inspect in the console, simpler to migrate, and we already use base64url over the wire").
4. **Repository classes** under `com.codeheadsystems.pkauth.persistence.dynamodb`:
   - Three `@DynamoDbBean` POJOs for the item types we land in Phase 5: `CredentialItem`, `ChallengeItem`, `UserItem`. Each one carries its own `TableSchema` and a `DynamoDbTable<T>` pointing at the right physical table (single-table for credentials/challenges, separate `PkAuthUsers` for users).
   - `DynamoDbCredentialRepository` — implements `CredentialRepository`. Save uses `PutItem` with a `ConditionExpression` to reject duplicates. Find-by-credential-id uses the GSI. List-by-user uses a `Query` on `pk = USER#{handle}` with `sk begins_with CRED#`. UpdateSignCount uses `UpdateItem` with `ConditionExpression sign_count < :newCount` so out-of-order writes are caught.
   - `DynamoDbChallengeStore` — implements `ChallengeStore`. Put writes with a TTL attribute. `takeOnce` is a `DeleteItem` with `ReturnValues = ALL_OLD`, which atomically removes and returns the prior value in one round-trip.
   - `DynamoDbUserLookup` — implements `UserLookup` on the separate `PkAuthUsers` table. `createOrGetUserHandle` reads via the username GSI; if no hit, mints a new handle and writes with `ConditionExpression attribute_not_exists(pk)` to make the race safe.
5. **Test infra** — `DynamoDbLocalExtension` (JUnit 5) starts the official `amazon/dynamodb-local:latest` Testcontainer once per test class, runs the bootstrapper, exposes a `DynamoDbEnhancedClient`. Decision in ADR 0007.
6. **Tests** — direct CRUD tests for each repo plus the parameterized ceremony test against this backend.
7. **ADR 0007** — `docs/adr/0007-dynamodb-local-vs-localstack.md` capturing the dynamodb-local choice and the trade-offs.
8. **ADR 0008** — `docs/adr/0008-dynamodb-single-table-design.md` capturing the key-design (pk/sk shapes, GSI design, base64url binary encoding, why the users table is separate).

## Sub-plan 3 — Shared parameterized ceremony test

Refactor `FullCeremonyTest` from `pk-auth-testkit` so the three scenarios (full registration → assertion → re-assertion, usernameless flow, duplicate save) can be driven against any combination of (CredentialRepository, ChallengeStore, UserLookup). Each persistence module gets a thin subclass that overrides the SPI factories.

Concretely: extract `CeremonyTestScenarios` (abstract base or static helpers) into `pk-auth-testkit/src/main/java`, leave the in-memory `FullCeremonyTest` as one concrete impl, and each persistence module ships its own concrete impl that wires its repos.

## Verify

- `./gradlew clean build test` green.
- Coverage ≥70% on each new module.
- Each ceremony test runs against its real backend (Testcontainers).
- Three new ADRs land under `docs/adr/`.

## Open question — one

**Should both new modules' tests run by default on `./gradlew test`, or be gated behind a CI/IT switch?** Testcontainers tests need Docker, which adds ~10-20s startup. Brief §9 says CI runs `gradlew check` on ubuntu-latest where Docker is available. I lean toward running them by default (consistent with the brief expectation) and accepting the local-dev cost, since the alternative is the persistence tests silently skipping on contributor machines. Confirm?

Proceeding with that assumption unless you say otherwise.
