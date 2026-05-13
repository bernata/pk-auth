# Contributing

## Working agreements

These mirror `pk-auth-build-brief.md` §12 — read that section for the full rationale.

1. **Phase discipline.** Complete the acceptance criteria for phase N (see brief §10) before starting phase N+1. Run `./gradlew check` between phases.
2. **Conventional commits.** Examples: `feat(core): ...`, `test(jdbi): ...`, `docs(adr): ...`, `build: ...`, `ci: ...`. Keep commits small and atomic.
3. **ADRs.** Non-trivial cross-module decisions get an ADR under `docs/adr/`, Nygard format. Number sequentially.
4. **Dependencies.** New libraries go through `gradle/libs.versions.toml` and are justified in the commit message or an ADR.
5. **No `TODO` in main** unless paired with a GitHub issue link.
6. **SPDX header** on every Java source file: `// SPDX-License-Identifier: MIT`. Spotless enforces this.
7. **Don't optimize prematurely.** Correct → tested → fast.

## Build

```sh
./gradlew check
```

JDK 21 required (Gradle toolchain will fetch one if needed).

## Running locally

Module-level READMEs (added in each phase) document the "5-minute integration" snippet and per-module specifics.
