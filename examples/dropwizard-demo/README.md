# pk-auth Dropwizard demo

Single-page demo of the [pk-auth Dropwizard adapter](../../pk-auth-dropwizard). Boots a
Dropwizard 5 application with the in-memory testkit SPIs, mounts the four passkey ceremony
endpoints under `/auth/passkeys/**`, and the admin endpoints under `/auth/admin/**`, then serves an
HTML+vanilla-JS page that drives the full flow with `navigator.credentials.{create,get}`.

## Run it

```bash
./gradlew :examples:dropwizard-demo:run
```

The application listens on **http://localhost:8080**. Open it in a passkey-capable browser
(Chrome / Edge / Safari / Firefox 130+) — your platform authenticator handles the WebAuthn
ceremony, the server stores the credential in memory, and the post-login page renders the
decoded JWT plus the admin controls.

To stop, hit `Ctrl-C`.

## What's in the demo

| Section | Endpoint | Notes |
|---|---|---|
| Register passkey | `POST /auth/passkeys/registration/start`, `POST /auth/passkeys/registration/finish` | First credential mints the user account; subsequent calls add additional passkeys (multi-passkey). |
| Sign in | `POST /auth/passkeys/authentication/start`, `POST /auth/passkeys/authentication/finish` | On success returns a pk-auth JWT (HS256). |
| Account summary | `GET /auth/admin/account` | Credential count, remaining backup codes, verification flags. |
| List / rename / delete passkeys | `GET/PATCH/DELETE /auth/admin/credentials*` | Last-credential guard rejects deletions that would lock the user out. |
| Backup codes | `POST /auth/admin/backup-codes/regenerate`, `GET /auth/admin/backup-codes/count` | Plaintext shown exactly once. |
| Magic link | `POST /auth/admin/email/start-verification` | `LoggingEmailSender` writes the URL to the server log — paste the token back into the page or call `complete-verification` directly. |
| Phone OTP | `POST /auth/admin/phone/start-verification`, `POST /auth/admin/phone/complete-verification` | `LoggingSmsSender` writes the code to the server log. |
| JWT contents | rendered client-side | Post-login the page shows the decoded JWT payload. |

## Persistence variants

The demo accepts a `--persistence` flag indicating which backing store to wire (brief §6.14):

```bash
./gradlew :examples:dropwizard-demo:run -Dpkauth.persistence=jdbi      # default
./gradlew :examples:dropwizard-demo:run -Dpkauth.persistence=dynamodb
```

In v0.x both flavors fall back to the in-memory SPIs so the demo runs out of the box. The
[`docker-compose.yml`](./docker-compose.yml) ships a Postgres 16 + DynamoDB Local stack for when
the JDBI / DynamoDB modules' "all-in-one" factories land (Phase 12 polish):

```bash
docker compose up -d
```

## End-to-end tests

Playwright drives the full registration → login → manage passkeys → backup codes →
magic link → OTP flow against Chrome's CDP virtual WebAuthn authenticator:

```sh
(cd examples/dropwizard-demo/e2e && npm install)
(cd examples/dropwizard-demo/e2e && npx playwright test)
```

The Playwright config's `webServer` block starts the demo on demand via
`./gradlew :examples:dropwizard-demo:run`. Set `PK_DEMO_EXTERNAL=1` to run against a
pre-started demo.

## Production caveats

This is a **demo**, not a production deployment recipe:

- The JWT signing secret is hard-coded.
- All persistence is process-local and erases on restart.
- `LoggingEmailSender` / `LoggingSmsSender` print verification tokens to the application log,
  which would be a security hole in production.

For production wiring, see `docs/operator-guide.md` (lands in Phase 12).
