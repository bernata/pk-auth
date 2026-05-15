# pk-auth Micronaut demo

A runnable Micronaut application exercising every pk-auth flow against the testkit's in-memory SPIs.

## Run

```sh
./gradlew :examples:micronaut-demo:run
```

The app boots on `http://localhost:8080`. Endpoints:

- `POST /auth/passkeys/registration/start`
- `POST /auth/passkeys/registration/finish`
- `POST /auth/passkeys/authentication/start`
- `POST /auth/passkeys/authentication/finish` — returns a JWT in both the body and the `Authorization` header on success.
- `GET /auth/admin/account` (requires `Authorization: Bearer <jwt>`)
- `GET /auth/admin/credentials`
- `PATCH /auth/admin/credentials/{credentialIdB64}` (body: `{"label":"..."}`)
- `DELETE /auth/admin/credentials/{credentialIdB64}`
- `POST /auth/admin/backup-codes/regenerate`
- `GET /auth/admin/backup-codes/count`
- `POST /auth/admin/email/start-verification` (body: `{"email":"..."}`)
- `POST /auth/admin/email/complete-verification` (body: `{"token":"..."}`) — unauthenticated.
- `POST /auth/admin/phone/start-verification` (body: `{"phone":"+15551234567"}`)
- `POST /auth/admin/phone/complete-verification` (body: `{"phone":"...","code":"123456"}`)

## Persistence flavors

The demo defaults to the testkit's in-memory SPIs so it runs without external infra. To wire real
persistence:

- **JDBI / Postgres** — add `pk-auth-persistence-jdbi` and provide a `Jdbi` bean.
- **DynamoDB** — add `pk-auth-persistence-dynamodb` and provide `DynamoDbClient` / `DynamoDbEnhancedClient` beans plus a `PkAuthDynamoTables`.

Replace the `InMemoryPersistenceFactory` with a factory that surfaces those repos.

## Frontend

A full browser walkthrough lands when the TS SDK from `clients/passkeys-browser` is wired
(Phase 11). For now the demo exposes only the JSON API.
