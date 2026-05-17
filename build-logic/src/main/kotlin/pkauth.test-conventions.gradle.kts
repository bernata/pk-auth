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

// Per-module coverage gates (≥80% on pk-auth-core, ≥70% on adapters) are wired in each module's
// build.gradle.kts via JacocoCoverageVerification, not centrally here.

tasks.named("check") {
    dependsOn(tasks.named("jacocoTestReport"))
}
