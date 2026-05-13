# pk-auth

A production-grade, passkeys-first authentication template for the JVM. Ships as a reusable library set across Spring Boot, Dropwizard, and Micronaut, with framework-neutral abstractions in the core.

## Status

Pre-alpha. Bootstrap in progress — see [`pk-auth-build-brief.md`](./pk-auth-build-brief.md) for the design and phase plan, and `docs/adr/` for architectural decisions as they land.

## Layout

The repository is a Gradle multi-module project. Module list and per-module briefs live in `pk-auth-build-brief.md` §5–§6.

## Build

```sh
./gradlew check
```

Requires JDK 21 (the Gradle toolchain will fetch one if not present).

## License

MIT — see [`LICENSE`](./LICENSE).
