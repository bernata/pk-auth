// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.autoconfigure.PkAuthAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Guards the production-safety invariant: the testkit's in-memory SPI defaults must NOT activate
 * unless the host opts in via {@code pkauth.dev-mode=true}. Without the flag, a host that forgets
 * to declare persistence beans should fail to start rather than silently boot against per-JVM
 * in-memory storage.
 *
 * <p>Required adapter config (RP id/name/origins, JWT issuer/audience/secret) is set explicitly on
 * every case so we reach the dev-mode guard rather than tripping the new fail-fast guards on those
 * properties.
 */
class PkAuthDevModeGuardTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(PkAuthAutoConfiguration.class))
          .withPropertyValues(
              "pkauth.relying-party.id=example.com",
              "pkauth.relying-party.name=test",
              "pkauth.relying-party.origins[0]=https://example.com",
              "pkauth.jwt.issuer=pk-auth-test",
              "pkauth.jwt.audience=pk-auth-test-clients",
              "pkauth.jwt.secret=integration-test-secret-must-be-32-bytes");

  @Test
  void contextFailsToStartWhenDevModeUnsetAndNoHostBeans() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasFailed()
                .getFailure()
                .isInstanceOf(UnsatisfiedDependencyException.class)
                .hasMessageContaining("CredentialRepository"));
  }

  @Test
  void contextFailsToStartWhenDevModeFalseAndNoHostBeans() {
    runner
        .withPropertyValues("pkauth.dev-mode=false")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .isInstanceOf(UnsatisfiedDependencyException.class)
                    .hasMessageContaining("CredentialRepository"));
  }

  @Test
  void inMemorySpiBeansActivateWhenDevModeTrue() {
    runner
        .withPropertyValues("pkauth.dev-mode=true")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(CredentialRepository.class)
                    .hasSingleBean(UserLookup.class)
                    .hasSingleBean(ChallengeStore.class)
                    .hasSingleBean(BackupCodeRepository.class)
                    .hasSingleBean(OtpRepository.class));
  }
}
