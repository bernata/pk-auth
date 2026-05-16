// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.magiclink.EmailSender;
import com.codeheadsystems.pkauth.magiclink.LoggingEmailSender;
import com.codeheadsystems.pkauth.otp.LoggingSmsSender;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.otp.SmsSender;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.autoconfigure.PkAuthAutoConfiguration;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Guards the OTP pepper policy: {@code pkauth.otp.pepper} is required in production. A per-startup
 * random pepper is only auto-generated when {@code pkauth.dev-mode=true}, since it invalidates
 * outstanding OTPs across restarts and across cluster instances.
 */
class PkAuthOtpPepperGuardTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(PkAuthAutoConfiguration.class))
          .withBean(CredentialRepository.class, InMemoryCredentialRepository::new)
          .withBean(UserLookup.class, InMemoryUserLookup::new)
          .withBean(ChallengeStore.class, InMemoryChallengeStore::new)
          .withBean(BackupCodeRepository.class, InMemoryBackupCodeRepository::new)
          .withBean(OtpRepository.class, InMemoryOtpRepository::new)
          .withBean(EmailSender.class, LoggingEmailSender::new)
          .withBean(SmsSender.class, LoggingSmsSender::new);

  @Test
  void contextFailsWhenPepperUnsetAndNotDevMode() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasFailed()
                .getFailure()
                .isInstanceOf(BeanCreationException.class)
                .hasMessageContaining("pkauth.otp.pepper"));
  }

  @Test
  void autoGeneratesPepperWhenDevModeTrueAndPepperUnset() {
    runner
        .withPropertyValues("pkauth.dev-mode=true")
        .run(ctx -> assertThat(ctx).hasSingleBean(OtpService.class));
  }

  @Test
  void acceptsExplicitlyConfiguredBase64Pepper() {
    byte[] secret = new byte[32];
    java.util.Arrays.fill(secret, (byte) 0x42);
    String encoded = Base64.getEncoder().encodeToString(secret);
    runner
        .withPropertyValues("pkauth.otp.pepper=" + encoded)
        .run(ctx -> assertThat(ctx).hasSingleBean(OtpService.class));
  }

  @Test
  void rejectsPepperShorterThan16Bytes() {
    byte[] tooShort = new byte[8];
    String encoded = Base64.getEncoder().encodeToString(tooShort);
    runner
        .withPropertyValues("pkauth.otp.pepper=" + encoded)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .isInstanceOf(BeanCreationException.class)
                    .hasMessageContaining("at least 16 bytes"));
  }
}
