# Phase 0 — Repo Scaffold Plan

Per section 10 of `pk-auth-build-brief.md`, Phase 0 sets up the empty multi-module Gradle project, convention plugins, CI, baseline docs, and ADR 0001. No production code yet. Acceptance: `./gradlew build` succeeds; CI is green.

## Task list (in execution order)

1. **Repository hygiene**
   - `.gitignore` (Gradle, IntelliJ, VS Code, macOS, Node for the future TS SDK).
   - `.editorconfig` (UTF-8, LF, 4-space Java, 2-space Kotlin/TS/YAML, final newline, trim trailing whitespace).
   - `LICENSE` (MIT, copyright "Ned Wolpert / Codehead Systems").
   - `README.md` skeleton: name, one-paragraph mission lifted from §1, architecture pointer (TBD), build status badge placeholder.
   - `CONTRIBUTING.md` skeleton: phase discipline, conventional commits, ADR process, how to run `./gradlew check`.

2. **Gradle wrapper**
   - Generate Gradle wrapper at the latest stable Gradle (currently 8.10.x). Pin version in `gradle/wrapper/gradle-wrapper.properties`.

3. **Version catalog** — `gradle/libs.versions.toml`
   - `[versions]`: java=21, junit=5.x, assertj, mockito, jackson, webauthn4j, nimbus-jose-jwt, jdbi, flyway, postgres-driver, testcontainers, awssdk, caffeine, micrometer, slf4j, logback, argon2, jspecify, errorprone, spotless, jacoco-tool, google-java-format.
   - `[libraries]`, `[bundles]`, `[plugins]` populated even if some are unused in Phase 0 — keeps later phases' diffs small.
   - Plugins: `spotless`, `errorprone`, `jacoco` (built-in), `dependency-versions` (e.g. `com.github.ben-manes.versions`) — only what Phase 0 actually applies; rest as commented stubs is *not* allowed (per §12.5 we justify additions per-need), so I'll only list what's used now and grow the catalog in later phases.

4. **Included build for convention plugins** — `build-logic/`
   - `build-logic/settings.gradle.kts` — declares an included build named `build-logic`, enables the version catalog from the parent via `dependencyResolutionManagement`.
   - `build-logic/build.gradle.kts` — applies `kotlin-dsl`, depends on Spotless, Error Prone, and any other plugins the conventions need.
   - Convention plugins under `build-logic/src/main/kotlin/`:
     - `pkauth.java-conventions.gradle.kts` — Java 21 toolchain, UTF-8, `-Xlint:all -Werror`, Error Prone, Spotless (Google Java Format), JSpecify on the classpath, common test deps wired *only when test conventions also applied*.
     - `pkauth.library-conventions.gradle.kts` — applies java conventions + `java-library` plugin; sets up `javadoc`/`sources` jars.
     - `pkauth.test-conventions.gradle.kts` — JUnit 5 platform, AssertJ, Mockito; JaCoCo with coverage rule placeholders (real thresholds turned on in later phases per §11; for Phase 0 the rule is configured but evaluates trivially since there's no code).
     - `pkauth.publish-conventions.gradle.kts` — `maven-publish` + signing config gated by env vars; POM metadata template. Wired but not exercised in Phase 0.

5. **Root project** — `settings.gradle.kts`, `build.gradle.kts`
   - `settings.gradle.kts`: `rootProject.name = "pk-auth"`, `includeBuild("build-logic")`, version catalog declared, no subprojects yet (added in later phases — Phase 0 must build green on its own).
   - Root `build.gradle.kts`: no plugins applied at root; root version `0.1.0-SNAPSHOT`; group `com.codeheadsystems`.

6. **GitHub Actions** — `.github/workflows/ci.yml`
   - Triggers: push to `main`, pull requests.
   - Single job, `ubuntu-latest`, `actions/setup-java@v4` with Temurin 21, `gradle/actions/setup-gradle@v4`, run `./gradlew check`.
   - Uploads JaCoCo report as artifact (will be empty in Phase 0).

7. **ADR 0001** — `docs/adr/0001-record-architecture-decisions.md`
   - Status: Accepted. Context: we will keep architectural decisions as Markdown ADRs in `docs/adr/`. Decision: adopt the Nygard ADR format, numbered sequentially. Consequences: every non-trivial cross-module decision gets one ADR; future ADRs listed in `pk-auth-build-brief.md` §5 are placeholders to be written when the relevant phase lands.

8. **SPDX headers**
   - Spotless rule in `pkauth.java-conventions` enforces `// SPDX-License-Identifier: MIT` at the top of every `.java` file. No Java files exist yet, but the rule is wired so Phase 1 cannot regress.

9. **Verify**
   - Run `./gradlew build` locally — must pass.
   - Run `./gradlew check` — must pass.
   - Commit as a series of small conventional commits (`chore: gradle wrapper`, `build: version catalog + convention plugins`, `ci: github actions`, `docs(adr): 0001 record architecture decisions`, etc.).
   - Push and confirm CI green before declaring Phase 0 done.

## Clarifying questions for the human

These are non-trivial and per §12.2 I would like an answer before executing rather than guess:

1. **LICENSE copyright holder** — should the line read `Copyright (c) 2026 Ned Wolpert` or `Copyright (c) 2026 Codehead Systems`? The brief uses the `com.codeheadsystems` namespace; that suggests the org, but personal projects often use the author.
2. **GitHub repo coordinates** — what is the eventual GitHub URL (e.g. `github.com/codeheadsystems/pk-auth` vs `github.com/nedwolpert/pk-auth`)? Needed for POM `<scm>` / `<url>` metadata in the publish conventions, and for the README badge URL.
3. **Maven Central publishing identity** — for the `pkauth.publish-conventions` POM developer/SCM fields and signing key id, who is the publisher of record? (Same answer probably resolves Q1 and Q2.)
4. **Gradle version pin** — happy to pin to the latest stable Gradle 8.x at time of bootstrap, or do you want a specific version (e.g. one your other projects already use)?
5. **Error Prone strictness in Phase 0** — fine to start with the default check set, or do you want a curated allow/deny list from the outset?
6. **Conformance workflow** — §9 says `conformance.yml` may be stubbed with a TODO and an ADR if FIDO conformance tooling is too heavy. Confirm I should stub it (with ADR placeholder) in Phase 0, or defer the whole file to a later phase.
7. **Branch protection / signed commits / GPG** — do you want signed commits required from the start? If yes, I'll add the doc note in `CONTRIBUTING.md`; the actual key configuration is yours to set up.
8. **Org-level CODEOWNERS / SECURITY.md** — include now (auth-adjacent repos usually want a `SECURITY.md` early) or defer to Phase 12 polish?

I will wait for approval (and answers to the above, where relevant) before writing any code.
