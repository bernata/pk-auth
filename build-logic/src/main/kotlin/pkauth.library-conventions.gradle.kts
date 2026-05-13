plugins {
    id("pkauth.java-conventions")
    `java-library`
}

java {
    withJavadocJar()
    withSourcesJar()
}

tasks.withType<JavaCompile>().configureEach {
    // Library modules are held to a stricter compile bar than build-logic itself.
    options.compilerArgs.add("-Werror")
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
        )
    }
}
