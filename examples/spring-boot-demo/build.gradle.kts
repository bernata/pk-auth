plugins {
    id("pkauth.java-conventions")
    id("pkauth.test-conventions")
    application
}

description = "pk-auth Spring Boot demo: single-page exercise of the full ceremony + admin surface."

tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

application {
    mainClass.set("com.codeheadsystems.pkauth.examples.spring.SpringBootDemoApplication")
}

dependencies {
    implementation(project(":pk-auth-spring-boot-starter"))
    implementation(project(":pk-auth-admin-api"))
    implementation(project(":pk-auth-testkit"))
    // Both persistence backends are on the demo classpath so the runtime `--persistence=` flag
    // can switch between them.
    implementation(project(":pk-auth-persistence-jdbi"))
    implementation(project(":pk-auth-persistence-dynamodb"))

    implementation(libs.spring.boot.starter)
    implementation(libs.spring.boot.starter.web)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.h2)
    runtimeOnly(libs.logback.classic)

    testImplementation(project(":pk-auth-testkit"))
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.security.test)
}

// Spring Boot transitively bundles slf4j-api and a logback impl; let those win at runtime to
// avoid duplicate logger conflicts vs the testkit/logback we already use elsewhere.
configurations.testImplementation {
    exclude(group = "org.mockito", module = "mockito-core")
    exclude(group = "org.mockito", module = "mockito-junit-jupiter")
}

tasks.named<Test>("test") {
    // Spring Boot's reflective DI on JDK 21 needs java.base/java.lang opened up for Mockito's
    // inline mocker (transitively pulled by spring-boot-starter-test) when proxying records.
    jvmArgs(
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
    )
}

tasks.named<JavaExec>("run") {
    // application plugin's run task — keep it as a convenience alongside bootRun-style invocation.
    jvmArgs(
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
    )
}
