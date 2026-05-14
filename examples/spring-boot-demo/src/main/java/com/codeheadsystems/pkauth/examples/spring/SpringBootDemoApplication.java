// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.examples.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Runnable entry point for the pk-auth Spring Boot demo. The auto-configuration in pk-auth-spring-
 * boot-starter wires every ceremony and admin endpoint; this class only provides the {@code
 * main(String[])} and a profile-conditional override for the {@code RelyingPartyConfig} (see {@link
 * DemoConfiguration}). To run:
 *
 * <pre>
 *   ./gradlew :examples:spring-boot-demo:bootRun           # JDBI persistence (Postgres if local)
 *   ./gradlew :examples:spring-boot-demo:bootRun \
 *       --args="--persistence=dynamodb"                    # DynamoDB persistence
 * </pre>
 *
 * <p>Without an explicit {@code --persistence=} flag the demo ships with the testkit's in-memory
 * SPIs (the autoconfigure defaults), so reviewers can boot the demo with no external services.
 */
@SpringBootApplication
public class SpringBootDemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringBootDemoApplication.class, args);
  }
}
