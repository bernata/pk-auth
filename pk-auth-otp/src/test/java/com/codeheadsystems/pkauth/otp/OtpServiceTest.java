// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OtpServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private static final UserHandle USER = UserHandle.of(new byte[] {1, 2, 3});
  private static final String PHONE = "+15551234567";

  private InMemoryOtpRepository repository;
  private RecordingSmsSender sms;
  private OtpService service;

  @BeforeEach
  void setUp() {
    repository = new InMemoryOtpRepository();
    sms = new RecordingSmsSender();
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    service =
        new OtpService(
            repository,
            sms,
            ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)),
            new SecureRandom(),
            argon2,
            Duration.ofMinutes(5),
            3,
            3,
            Duration.ofMinutes(15));
  }

  @Test
  void sendIssuesAndDispatchesCode() {
    OtpService.SendResult result = service.send(USER, PHONE);
    assertThat(result).isInstanceOf(OtpService.SendResult.Sent.class);
    assertThat(sms.messages).hasSize(1);
    assertThat(sms.messages.get(0).message).contains("verification code");
  }

  @Test
  void verifyAcceptsMatchingCodeOnce() {
    service.send(USER, PHONE);
    String code = sms.lastCode();

    assertThat(service.verify(USER, PHONE, code))
        .isInstanceOf(OtpService.VerifyResult.Success.class);
    // After consume, no active OTP.
    assertThat(service.verify(USER, PHONE, code))
        .isInstanceOf(OtpService.VerifyResult.NoActiveOtp.class);
  }

  @Test
  void verifyMismatchDecrementsRemainingAttempts() {
    service.send(USER, PHONE);
    OtpService.VerifyResult first = service.verify(USER, PHONE, "000000");
    assertThat(first)
        .isInstanceOfSatisfying(
            OtpService.VerifyResult.CodeMismatch.class,
            m -> assertThat(m.remainingAttempts()).isEqualTo(2));
    service.verify(USER, PHONE, "000000");
    service.verify(USER, PHONE, "000000");
    assertThat(service.verify(USER, PHONE, "000000"))
        .isInstanceOf(OtpService.VerifyResult.AttemptsExceeded.class);
  }

  @Test
  void sendRateLimits() {
    service.send(USER, PHONE);
    service.send(USER, PHONE);
    service.send(USER, PHONE);
    assertThat(service.send(USER, PHONE))
        .isInstanceOfSatisfying(
            OtpService.SendResult.RateLimited.class,
            r -> assertThat(r.countInWindow()).isGreaterThanOrEqualTo(3));
  }

  @Test
  void expiredOtpIsRejected() {
    service.send(USER, PHONE);
    String code = sms.lastCode();
    OtpService advanced =
        new OtpService(
            repository,
            sms,
            ClockProvider.fromClock(Clock.fixed(NOW.plus(Duration.ofMinutes(10)), ZoneOffset.UTC)),
            new SecureRandom(),
            Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id),
            Duration.ofMinutes(5),
            3,
            3,
            Duration.ofMinutes(15));
    assertThat(advanced.verify(USER, PHONE, code))
        .isInstanceOf(OtpService.VerifyResult.Expired.class);
  }

  @Test
  void smsSendersDoNotThrowForLoggingFlavor() {
    new LoggingSmsSender().sendOtp(PHONE, "test");
  }

  /** Captures sends so tests can pluck the dispatched code out of the message body. */
  private static final class RecordingSmsSender implements SmsSender {
    private final List<Sent> messages = new ArrayList<>();

    @Override
    public void sendOtp(String phoneE164, String message) {
      messages.add(new Sent(phoneE164, message));
    }

    String lastCode() {
      String last = messages.get(messages.size() - 1).message;
      // Pull the trailing token off "Your verification code is XXXXXX".
      int idx = last.lastIndexOf(' ');
      return last.substring(idx + 1);
    }

    record Sent(String phone, String message) {}
  }
}
