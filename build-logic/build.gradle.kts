plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.build.spotless.plugin)
    implementation(libs.build.errorprone.plugin)

    // Expose the version catalog (`libs.*`) to precompiled script plugins under src/main/kotlin.
    // Without this, accessors like `libs.versions.java.get()` are unresolved in the convention
    // plugins themselves. See: https://github.com/gradle/gradle/issues/15383
    implementation(files(libs.javaClass.superclass.protectionDomain.codeSource.location))
}
