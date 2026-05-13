plugins {
    java
    jacoco
}

val libs = the<org.gradle.accessors.dm.LibrariesForLibs>()

dependencies {
    "testImplementation"(platform("org.junit:junit-bom:${libs.versions.junit.jupiter.get()}"))
    "testImplementation"(libs.bundles.test)
    "testRuntimeOnly"(libs.junit.platform.launcher)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

jacoco {
    // Pin the JaCoCo tooling version centrally so all modules report against the same engine.
    toolVersion = "0.8.12"
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.named("test"))
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

// Coverage gates are intentionally NOT wired in Phase 0 — there is no production code yet, so any
// minimum threshold would force an immediate spurious failure. The brief (§11) calls for ≥80% on
// pk-auth-core and ≥70% on adapters; those rules get enabled in Phase 1+ once real code lands.

tasks.named("check") {
    dependsOn(tasks.named("jacocoTestReport"))
}
