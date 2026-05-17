plugins {
    id("pkauth.library-conventions")
    id("pkauth.test-conventions")
    id("pkauth.publish-conventions")
}

description = "pk-auth Micronaut adapter: @Factory + ceremony controller + admin controller + JWT filter."

tasks.withType<JavaCompile>().configureEach {
    // Micronaut's annotation processor + Java 21 emit a noisy "No processor claimed any of these
    // annotations" warning at javac. The processor itself runs correctly; -Werror just elevates
    // the warning to fatal. Suppress `processing` lint on this module.
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:-requires-automatic",
            "-Xlint:-requires-transitive-automatic",
            "-Xlint:-processing",
        ),
    )
}

dependencies {
    api(project(":pk-auth-core"))
    api(project(":pk-auth-jwt"))
    api(project(":pk-auth-backup-codes"))
    api(project(":pk-auth-magic-link"))
    api(project(":pk-auth-otp"))
    api(project(":pk-auth-refresh-tokens"))
    api(project(":pk-auth-admin-api"))
    api(libs.micronaut.context)
    api(libs.micronaut.http)
    api(libs.micronaut.http.server.netty)
    implementation(libs.micronaut.runtime)
    implementation(libs.micronaut.jackson.databind)
    implementation(libs.slf4j.api)

    // Micronaut's @Inject site references the JDBI errorprone @GuardedBy via the persistence
    // modules. Same trick as pk-auth-persistence-jdbi.
    compileOnly("com.google.errorprone:error_prone_annotations:2.49.0")
    testCompileOnly("com.google.errorprone:error_prone_annotations:2.49.0")

    annotationProcessor(libs.micronaut.inject.java)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(libs.micronaut.http.client)
    testImplementation(libs.micronaut.test.junit5)
    testAnnotationProcessor(libs.micronaut.inject.java)
    testRuntimeOnly(libs.logback.classic)
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.70".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn("jacocoTestCoverageVerification")
}
