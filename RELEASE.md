# Releasing pk-auth

This document explains how to publish the pk-auth libraries to Maven Central.

## What gets published

Every release publishes the same set of 12 artifacts, all under
`com.codeheadsystems` and sharing one version:

- `pk-auth-core`, `pk-auth-jwt`, `pk-auth-admin-api`
- `pk-auth-backup-codes`, `pk-auth-magic-link`, `pk-auth-otp`
- `pk-auth-persistence-jdbi`, `pk-auth-persistence-dynamodb`
- `pk-auth-testkit`
- `pk-auth-spring-boot-starter`, `pk-auth-dropwizard`, `pk-auth-micronaut`

The demo applications under `examples/` are intentionally **not** published.

## Prerequisites (one-time)

These repository secrets must exist on the GitHub repo (they are shared with
`hofmann-elimination` under the same `codeheadsystems` org, so on a fresh fork
you only need to set them once at the org level):

| Secret                    | Purpose                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| `CENTRAL_PORTAL_USERNAME` | Sonatype Central Portal user-token username                          |
| `CENTRAL_PORTAL_PASSWORD` | Sonatype Central Portal user-token password                          |
| `GPG_PRIVATE_KEY`         | Base64-encoded ASCII-armored private key used to sign artifacts      |
| `GPG_PASSPHRASE`          | Passphrase for the GPG key                                           |
| `GPG_KEY_ID`              | Long key id (or fingerprint) of the signing key                      |

To generate the base64 form of the private key locally:

```sh
gpg --armor --export-secret-keys YOUR_KEY_ID | base64 -w 0
```

The signing key must be published to a public keyserver (e.g.
`keys.openpgp.org`) so Central Portal can verify signatures.

## Release modes

Two GitHub Actions workflows are configured:

### A. Tagged release (preferred for planned releases)

Push a semver tag matching `vMAJOR.MINOR.PATCH` (or
`vMAJOR.MINOR.PATCH-suffix` for pre-releases) and the
`Tag Release to Maven Central` workflow takes over.

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`settings.gradle.kts` reads the exact tag at build time and uses it as the
project version, so you do **not** need to edit `gradle.properties` first.

A pre-release suffix (e.g. `v0.2.0-rc.1`) automatically marks the GitHub
release as a pre-release.

### B. Manual release (one-click patch bump)

For a quick patch release with no special version planning, go to **Actions →
Manual Build Release to Maven Central → Run workflow**. The workflow:

1. Reads the latest `vX.Y.Z` tag and increments the patch component.
2. Creates and pushes the new tag.
3. Runs the same publish + GitHub-release flow as the tagged path.

Use the tagged path (mode A) when the release should be a minor or major bump,
when you want a pre-release suffix, or when you want the version pinned in the
commit history before the workflow runs.

## What the workflow does

Both workflows perform the same steps:

1. Checkout with full history (`fetch-depth: 0`) so `git describe` can see the
   tag.
2. Validate the tag matches semver.
3. Set up JDK 21 + Gradle.
4. Confirm Gradle's resolved version equals the tag's version.
5. `./gradlew clean build test --stacktrace` — full build and test gate; a
   failure here aborts the release.
6. Import the GPG key and configure non-interactive signing.
7. `./gradlew publishAggregationToCentralPortal` — builds, signs, and uploads
   every module in a single bundle to the Central Portal.
8. Build per-module `-sources.jar` and `-javadoc.jar` archives.
9. Create a GitHub release with all 12 module jars attached and a copy-paste
   `implementation(...)` snippet in the body.

## Verifying the release

After the workflow succeeds:

1. **GitHub release** appears at <https://github.com/codeheadsystems/pk-auth/releases>
   with all jars attached.
2. **Maven Central** can take up to ~2 hours to index. Check status at
   <https://central.sonatype.com/publishing/deployments> (Central Portal
   dashboard). The deployment moves through `VALIDATING → VALIDATED → PUBLISHING
   → PUBLISHED`.
3. **README badges** (driven by `img.shields.io/maven-central/v/...`) will
   refresh on their own once Central serves the new version — usually within
   an hour of publish completing.

## Local dry run

To sanity-check a release locally before tagging:

```sh
./gradlew clean build test                             # the gate the workflow uses
./gradlew publishMavenJavaPublicationToMavenLocal      # write jars to ~/.m2/repository
./gradlew tasks --group publishing                     # confirm the aggregation task is present
```

Local publish to Central Portal requires `~/.gradle/gradle.properties` to
contain `centralPortalUsername` / `centralPortalPassword` and a working
`signing.gnupg.keyName`. Most contributors do not need this — push a tag and
let CI handle it.

## Troubleshooting

- **Tag/version mismatch.** The `Verify version matches tag` step fails when
  `gradle.properties` version doesn't match the tag. Because
  `settings.gradle.kts` overrides version from the tag, this normally only
  fires when the tag itself is malformed.
- **GPG import fails.** Verify `GPG_PRIVATE_KEY` is base64 of the **private**
  key (`gpg --export-secret-keys`, not `--export`), encoded with `base64 -w 0`
  (single line, no wrap).
- **Central Portal rejects the bundle.** Check the dashboard's deployment
  detail page — the most common cause is the signing key not being on a public
  keyserver. Re-upload to `keys.openpgp.org` and retry.
- **Artifact not visible after 2 hours.** Re-check the Central Portal
  deployment status; if it shows `PUBLISHED`, the indexer is just slow —
  artifacts are already downloadable via direct URL.
- **`publishAggregationToCentralPortal` task missing.** Means the
  `com.gradleup.nmcp.settings` plugin in `settings.gradle.kts` did not load.
  Confirm the plugin id and version, then re-run with `--refresh-dependencies`.

## Rolling back a release

Maven Central releases are immutable — a published version cannot be
overwritten or deleted. To recover from a bad release, cut a new patch (or
minor) release with the fix and update consumers. Do not attempt to re-publish
the same version.
