import net.ltgt.gradle.errorprone.errorprone

plugins {
    java
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
}

val libs = the<org.gradle.accessors.dm.LibrariesForLibs>()

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
    }
}

dependencies {
    compileOnly(libs.jspecify)
    errorprone(libs.build.errorprone.core)
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // -Werror is intentionally omitted in Phase 0: build-logic compilation already runs with strict
    // settings, and adapter modules may need to fine-tune lints per-module. The brief calls for
    // -Xlint:all -Werror on production modules — that gets layered on in library-conventions where
    // we know it is safe.
    //
    // -XDaddTypeAnnotationsToSymbol=true is required by Error Prone 2.27+ on JDK 21 so that
    // type-use annotations (e.g. JSpecify's @Nullable) are visible on symbols at analysis time.
    // Without it Error Prone refuses to start. See
    // https://github.com/google/error-prone/issues/4011
    options.compilerArgs.addAll(
        listOf("-Xlint:all", "-parameters", "-XDaddTypeAnnotationsToSymbol=true"),
    )
    options.errorprone.disableWarningsInGeneratedCode = true
    // Default Error Prone check set, with one project-wide override:
    // pk-auth's wire contract is WebAuthn's, which is binary-heavy (challenge bytes, credential
    // ids, COSE-encoded public keys, signatures, …). Modeling those as `byte[]` record
    // components is intentional; each affected record overrides equals/hashCode to compare by
    // content, so the default-record equality pitfall ErrorProne is protecting against doesn't
    // apply. Suppress the check globally rather than annotating every record.
    options.errorprone.disable("ArrayRecordComponent")
}

spotless {
    java {
        target("src/**/*.java")
        googleJavaFormat(libs.versions.google.java.format.get())
        licenseHeader("// SPDX-License-Identifier: MIT")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
    kotlinGradle {
        target("*.gradle.kts")
        trimTrailingWhitespace()
        endWithNewline()
    }
}

tasks.named("check") {
    dependsOn("spotlessCheck")
}

// Spotless + google-java-format intermittently fails class loading
// (`NoClassDefFoundError com/google/common/collect/ImmutableList$ReverseImmutableList`) when its
// outputs are restored from the Gradle build cache. Disabling cache hits for the spotless tasks
// avoids the bad-cache-state pathway; the formatter itself works correctly on a fresh run.
tasks.matching { it.name.startsWith("spotless") }.configureEach {
    outputs.cacheIf { false }
}
