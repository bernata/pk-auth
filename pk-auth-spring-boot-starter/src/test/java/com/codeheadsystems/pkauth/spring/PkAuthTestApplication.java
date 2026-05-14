// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.testkit.PkAuthFixtures;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Minimal Spring Boot application for {@link org.springframework.boot.test.context.SpringBootTest}.
 * It opts in to the starter via component-scan of the autoconfigure packages and overrides the
 * relying-party config so {@link PkAuthFixtures}'s {@code example.com} matches the testkit's {@code
 * FakeAuthenticator}.
 */
@SpringBootApplication
public class PkAuthTestApplication {

  /**
   * Override the property-based default so the {@code FakeAuthenticator}'s {@code example.com}
   * origin is on the allow-list. The starter's default uses {@code localhost:8080} which {@code
   * FakeAuthenticator} doesn't sign for.
   */
  @Bean
  @Primary
  public RelyingPartyConfig testRelyingPartyConfig() {
    return PkAuthFixtures.defaultRelyingParty();
  }
}
