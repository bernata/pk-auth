plugins {
    `maven-publish`
    signing
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])

            groupId = project.group.toString()
            artifactId = project.name
            version = project.version.toString()

            pom {
                name.set(project.findProperty("pomName")?.toString() ?: project.name)
                description.set(
                    project.findProperty("pomDescription")?.toString()
                        ?: "pk-auth: passkeys-first authentication template for the JVM"
                )
                url.set("https://github.com/codeheadsystems/pk-auth")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("wolpert")
                        name.set("Ned Wolpert")
                        email.set("ned.wolpert@gmail.com")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/codeheadsystems/pk-auth.git")
                    developerConnection.set("scm:git:ssh://git@github.com:codeheadsystems/pk-auth.git")
                    url.set("https://github.com/codeheadsystems/pk-auth")
                }
            }
        }
    }
}

signing {
    // Signing is opt-in: only required when publishing a non-SNAPSHOT release AND credentials are
    // configured (mirrors the hofmann-elimination convention so the same local + CI setup works).
    val signingRequired = project.hasProperty("signing.gnupg.keyName")
        || System.getenv("GPG_KEY_ID") != null

    isRequired = signingRequired && !version.toString().endsWith("SNAPSHOT")

    useGpgCmd()
    sign(publishing.publications["mavenJava"])
}

tasks.register("verifyPublishConfig") {
    doLast {
        println("Group: ${project.group}")
        println("Artifact: ${project.name}")
        println("Version: ${project.version}")
        println("Is SNAPSHOT: ${version.toString().endsWith("SNAPSHOT")}")
    }
}
