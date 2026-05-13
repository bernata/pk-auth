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

tasks.register("phaseStatus") {
    group = "documentation"
    description = "Print the current bootstrap phase per pk-auth-build-brief.md §10."
    doLast {
        println("pk-auth phase 0 — repo scaffold. See pk-auth-build-brief.md for the full plan.")
    }
}
