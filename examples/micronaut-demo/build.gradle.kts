plugins {
    application
    id("pkauth.java-conventions")
}

description = "pk-auth Micronaut demo app."

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:-requires-automatic",
            "-Xlint:-requires-transitive-automatic",
            "-Xlint:-processing",
        ),
    )
}

application {
    mainClass.set("com.codeheadsystems.pkauth.demo.micronaut.MicronautDemoApplication")
}

dependencies {
    implementation(project(":pk-auth-micronaut"))
    implementation(project(":pk-auth-testkit"))
    implementation(libs.micronaut.runtime)
    runtimeOnly(libs.logback.classic)

    annotationProcessor(libs.micronaut.inject.java)

    testImplementation(libs.micronaut.test.junit5)
    testImplementation(libs.micronaut.http.client)
    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.0.3")
    testAnnotationProcessor(libs.micronaut.inject.java)
}

// Bundle the @pk-auth/passkeys-browser SDK so the demo's index page can import it
// as an ES module. dist/ is committed (see clients/passkeys-browser/README.md).
val passkeysBrowserDist = rootProject.file("clients/passkeys-browser/dist")
tasks.named<Copy>("processResources") {
    from(passkeysBrowserDist) {
        include("index.js", "index.js.map")
        into("public/passkeys-browser")
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
