# pk-auth Spring Boot demo

A single-page exercise of every flow in the pk-auth credential layer: passkey registration
(including multi-passkey), passkey login, list/rename/delete credentials, regenerate
backup codes (view-once), magic-link email verification, SMS OTP phone verification, and
account summary. The post-login UI also decodes the issued JWT so you can see the claims.

## Running

The default profile boots with the testkit's in-memory adapters and needs no external
services:

```sh
./gradlew :examples:spring-boot-demo:bootRun
# open http://localhost:8080
```

Use the `application` plugin's `run` task interchangeably:

```sh
./gradlew :examples:spring-boot-demo:run
```

### Switching persistence backends

Brief §6.14 requires both JDBI and DynamoDB variants. Start the external services with
`docker compose up -d`, then point the demo at one or the other:

```sh
# Postgres-backed (Flyway migrations run at startup):
./gradlew :examples:spring-boot-demo:bootRun --args='--demo.persistence=jdbi'

# DynamoDB Local:
./gradlew :examples:spring-boot-demo:bootRun --args='--demo.persistence=dynamodb'
```

> The wiring beans for `jdbi` and `dynamodb` are stubbed out in this demo — at the
> moment the runtime flag toggles the property, but the actual `Jdbi` / `DynamoDbClient`
> beans need to be supplied by the host app. A future iteration of this demo will ship
> those as profile-conditional `@Configuration` classes. For now, the `memory` profile
> is the supported runnable path; the JDBI / DynamoDB autoconfigs in the starter are
> validated by the starter's tests.

## Endpoint surface

The demo's HTML hits the standard pk-auth endpoints — there's no demo-specific REST
surface beyond `GET /` returning the SPA. The endpoint table:

| Method | Path                                              | Purpose |
|--------|---------------------------------------------------|---------|
| POST   | /auth/passkeys/registration/start                 | Begin registration |
| POST   | /auth/passkeys/registration/finish                | Finish registration |
| POST   | /auth/passkeys/authentication/start               | Begin assertion |
| POST   | /auth/passkeys/authentication/finish              | Finish assertion (mints JWT) |
| GET    | /auth/admin/account                               | Current user summary |
| GET    | /auth/admin/credentials                           | List passkeys |
| PATCH  | /auth/admin/credentials/{credentialId}            | Rename a passkey |
| DELETE | /auth/admin/credentials/{credentialId}            | Delete a passkey |
| POST   | /auth/admin/backup-codes/regenerate               | View-once plaintext codes |
| GET    | /auth/admin/backup-codes/count                    | Remaining count |
| POST   | /auth/admin/email/start-verification              | Send magic link |
| POST   | /auth/admin/email/complete-verification           | Consume token (unauth) |
| POST   | /auth/admin/phone/start-verification              | Send OTP |
| POST   | /auth/admin/phone/complete-verification           | Verify OTP |

## Notes

- Magic-link tokens and SMS OTPs are logged to the server console (the demo's senders
  are `LoggingEmailSender` / `LoggingSmsSender`). Copy them out of the log and paste
  back into the form to complete the corresponding flow.
- The demo intentionally uses inline HTML and vanilla JS. The shared TypeScript SDK
  (`clients/passkeys-browser`) lands in Phase 11; the demos will be rewired to consume
  it then.
- WebAuthn requires a secure origin. `http://localhost:8080` is secure-by-loopback in
  every major browser. Running the demo behind a remote host needs HTTPS.
- Virtual threads are enabled (`spring.threads.virtual.enabled=true`) per brief §11.
