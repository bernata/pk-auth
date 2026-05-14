pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "pk-auth"

includeBuild("build-logic")

// Subprojects are added phase by phase (see pk-auth-build-brief.md §10).
include("pk-auth-core")
include("pk-auth-jwt")
include("pk-auth-backup-codes")
include("pk-auth-magic-link")
include("pk-auth-otp")
include("pk-auth-admin-api")
include("pk-auth-persistence-jdbi")
include("pk-auth-persistence-dynamodb")
include("pk-auth-testkit")
