// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository.StoredOtp;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies 6-digit numeric SMS OTPs for phone verification (brief §6.5). Defaults:
 * 5-minute TTL, max 5 verification attempts per code, rate limit 3 codes per (user, phone) per
 * 15-minute window.
 */
public final class OtpService {

  /** Length of the OTP in digits. */
  public static final int OTP_LENGTH = 6;

  /** Default TTL for an issued OTP. */
  public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

  /** Default maximum verification attempts per OTP. */
  public static final int DEFAULT_MAX_ATTEMPTS = 5;

  /** Default rate limit: 3 codes per 15-minute window. */
  public static final int DEFAULT_RATE_LIMIT = 3;

  /** Default rate-limit window. */
  public static final Duration DEFAULT_RATE_WINDOW = Duration.ofMinutes(15);

  /** Result of a send attempt. */
  public sealed interface SendResult {
    /** OTP was generated and dispatched to the SMS sender. */
    record Sent(String otpId) implements SendResult {}

    /** Rate limit hit; the caller must wait before requesting another OTP. */
    record RateLimited(int countInWindow) implements SendResult {}
  }

  /** Result of a verify attempt. */
  public sealed interface VerifyResult {
    /** Code matched; the OTP record is consumed. */
    record Success() implements VerifyResult {}

    /** No active OTP for this (user, phone). */
    record NoActiveOtp() implements VerifyResult {}

    /** Code did not match the stored hash. */
    record CodeMismatch(int remainingAttempts) implements VerifyResult {}

    /** Too many failed attempts on this OTP. */
    record AttemptsExceeded() implements VerifyResult {}

    /** OTP existed but has expired. */
    record Expired() implements VerifyResult {}
  }

  private static final Logger LOG = LoggerFactory.getLogger(OtpService.class);

  private final OtpRepository repository;
  private final SmsSender smsSender;
  private final ClockProvider clockProvider;
  private final SecureRandom random;
  private final Argon2 argon2;
  private final Duration ttl;
  private final int maxAttempts;
  private final int rateLimit;
  private final Duration rateWindow;

  public OtpService(OtpRepository repository, SmsSender smsSender, ClockProvider clockProvider) {
    this(
        repository,
        smsSender,
        clockProvider,
        new SecureRandom(),
        Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id),
        DEFAULT_TTL,
        DEFAULT_MAX_ATTEMPTS,
        DEFAULT_RATE_LIMIT,
        DEFAULT_RATE_WINDOW);
  }

  /** Test seam allowing override of every tunable parameter. */
  public OtpService(
      OtpRepository repository,
      SmsSender smsSender,
      ClockProvider clockProvider,
      SecureRandom random,
      Argon2 argon2,
      Duration ttl,
      int maxAttempts,
      int rateLimit,
      Duration rateWindow) {
    this.repository = Objects.requireNonNull(repository, "repository");
    this.smsSender = Objects.requireNonNull(smsSender, "smsSender");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.random = Objects.requireNonNull(random, "random");
    this.argon2 = Objects.requireNonNull(argon2, "argon2");
    this.ttl = Objects.requireNonNull(ttl, "ttl");
    this.maxAttempts = maxAttempts;
    this.rateLimit = rateLimit;
    this.rateWindow = Objects.requireNonNull(rateWindow, "rateWindow");
  }

  /** Generates a new OTP, persists it, and hands it to the {@link SmsSender}. */
  public SendResult send(UserHandle user, String phoneE164) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(phoneE164, "phoneE164");

    Instant now = clockProvider.now();
    int recent = repository.countSince(user, phoneE164, now.minus(rateWindow));
    if (recent >= rateLimit) {
      LOG.info("otp.send rate-limited user={} phone={} count={}", user, phoneE164, recent);
      return new SendResult.RateLimited(recent);
    }

    String code = newCode();
    char[] codeChars = code.toCharArray();
    String hash;
    try {
      hash = argon2.hash(2, 65_536, 1, codeChars, StandardCharsets.UTF_8);
    } finally {
      argon2.wipeArray(codeChars);
    }

    String otpId = UUID.randomUUID().toString();
    repository.save(
        new StoredOtp(otpId, user, phoneE164, hash, 0, maxAttempts, false, now, now.plus(ttl)));
    smsSender.sendOtp(phoneE164, "Your verification code is " + code);
    LOG.info("otp.send issued user={} phone={} otpId={}", user, phoneE164, otpId);
    return new SendResult.Sent(otpId);
  }

  /** Verifies a candidate code against the most recent active OTP for (user, phone). */
  public VerifyResult verify(UserHandle user, String phoneE164, String candidate) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(phoneE164, "phoneE164");
    Objects.requireNonNull(candidate, "candidate");

    Optional<StoredOtp> activeOpt = repository.findLatestActive(user, phoneE164);
    if (activeOpt.isEmpty()) {
      return new VerifyResult.NoActiveOtp();
    }
    StoredOtp active = activeOpt.get();
    Instant now = clockProvider.now();
    if (now.isAfter(active.expiresAt())) {
      return new VerifyResult.Expired();
    }
    if (active.attempts() >= active.maxAttempts()) {
      return new VerifyResult.AttemptsExceeded();
    }

    char[] candidateChars = candidate.toCharArray();
    boolean matches;
    try {
      matches = argon2.verify(active.hashedCode(), candidateChars, StandardCharsets.UTF_8);
    } finally {
      argon2.wipeArray(candidateChars);
    }
    if (matches) {
      repository.consume(active.otpId());
      LOG.info("otp.verify success user={} otpId={}", user, active.otpId());
      return new VerifyResult.Success();
    }
    repository.incrementAttempts(active.otpId());
    int remaining = Math.max(0, active.maxAttempts() - (active.attempts() + 1));
    LOG.info("otp.verify mismatch user={} otpId={} remaining={}", user, active.otpId(), remaining);
    return new VerifyResult.CodeMismatch(remaining);
  }

  private String newCode() {
    StringBuilder sb = new StringBuilder(OTP_LENGTH);
    for (int i = 0; i < OTP_LENGTH; i++) {
      sb.append(random.nextInt(10));
    }
    return sb.toString();
  }
}
