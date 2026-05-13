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
    options.compilerArgs.addAll(listOf("-Xlint:all", "-parameters"))
    options.errorprone.disableWarningsInGeneratedCode = true
    // Default Error Prone check set, per Phase 0 plan.
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
