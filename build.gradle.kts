// Root build for pk-auth. Phase 0 keeps this near-empty; convention plugins live in build-logic/
// and are applied per-module starting in Phase 1.
//
// The `base` plugin gives the root project the standard lifecycle tasks (build, check, clean,
// assemble) so `./gradlew check` and `./gradlew build` succeed even with zero subprojects.
plugins {
    base
}

// `test` is a lifecycle task at the root so the standard `gradle clean build test` workflow
// resolves even when no test-bearing subprojects exist yet. Once subprojects with the java
// plugin are added in Phase 1+, Gradle's multi-project task expansion runs each subproject's
// own `test` task automatically; this root task continues to act as the aggregating entry
// point.
tasks.register("test") {
    group = "verification"
    description = "Lifecycle task that aggregates `test` across all subprojects."
    dependsOn(subprojects.map { it.tasks.matching { t -> t.name == "test" } })
}

// Root-level task that builds the @pk-auth/passkeys-browser SDK bundle into its `dist/` directory.
// The three example apps' processResources tasks depend on this so a fresh clone produces the
// bundle without a manual npm step. `dist/` is gitignored — the Gradle build is the source of
// truth, and tsup's inputs/outputs let Gradle skip the npm work on incremental rebuilds.
val passkeysBrowserDir = layout.projectDirectory.dir("clients/passkeys-browser")

tasks.register<Exec>("buildPasskeysBrowserSdk") {
    group = "build"
    description = "Builds the @pk-auth/passkeys-browser ESM/CJS bundles via npm + tsup."
    workingDir = passkeysBrowserDir.asFile
    // `npm ci` honors the committed package-lock.json for deterministic installs; `npm run build`
    // invokes tsup (see clients/passkeys-browser/tsup.config.ts).
    commandLine("sh", "-c", "npm ci --no-audit --no-fund && npm run build")
    inputs.dir(passkeysBrowserDir.dir("src"))
    inputs.file(passkeysBrowserDir.file("package.json"))
    inputs.file(passkeysBrowserDir.file("package-lock.json"))
    inputs.file(passkeysBrowserDir.file("tsup.config.ts"))
    inputs.file(passkeysBrowserDir.file("tsconfig.json"))
    outputs.dir(passkeysBrowserDir.dir("dist"))
}

tasks.register("phaseStatus") {
    group = "documentation"
    description = "Print the current bootstrap phase per pk-auth-build-brief.md §10."
    doLast {
        println("pk-auth phase 0 — repo scaffold. See pk-auth-build-brief.md for the full plan.")
    }
}
