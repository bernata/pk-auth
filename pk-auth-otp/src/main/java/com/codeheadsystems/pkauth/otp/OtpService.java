// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository.StoredOtp;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies 6-digit numeric SMS OTPs for phone verification (brief §6.5). Defaults:
 * 5-minute TTL, max 5 verification attempts per code, rate limit 3 codes per (user, phone) per
 * 15-minute window.
 *
 * <p>OTP codes are hashed with {@code HMAC-SHA256(pepper, code)} rather than Argon2id. The 10^6
 * search space is small enough that Argon2id offers little additional protection, and the
 * per-attempt limit enforced by the repository is the primary brute-force defence. A server-side
 * pepper (never stored in the database) means a DB dump alone cannot enumerate codes; the attacker
 * also needs the pepper secret.
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

  private static final String HMAC_ALGORITHM = "HmacSHA256";

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

  /**
   * Server-side pepper used as the HMAC key when hashing OTP codes. This value must never be stored
   * in the database — a DB dump alone cannot enumerate codes without it. The 10^6 search space is
   * manageable only if an attacker also possesses the pepper; combined with per-attempt limiting
   * this provides defence-in-depth.
   */
  private final byte[] pepper;

  private final Duration ttl;
  private final int maxAttempts;
  private final int rateLimit;
  private final Duration rateWindow;

  /**
   * Convenience constructor using all defaults.
   *
   * @param repository OTP persistent store
   * @param smsSender delivery adapter
   * @param clockProvider time source
   * @param pepper server-side HMAC key; must be at least 16 bytes
   */
  public OtpService(
      OtpRepository repository, SmsSender smsSender, ClockProvider clockProvider, byte[] pepper) {
    this(
        repository,
        smsSender,
        clockProvider,
        new SecureRandom(),
        pepper,
        DEFAULT_TTL,
        DEFAULT_MAX_ATTEMPTS,
        DEFAULT_RATE_LIMIT,
        DEFAULT_RATE_WINDOW);
  }

  /**
   * Full constructor allowing override of every tunable parameter (test seam and advanced
   * configuration).
   *
   * @param pepper server-side HMAC key; a DB dump without this value cannot brute-force codes
   */
  public OtpService(
      OtpRepository repository,
      SmsSender smsSender,
      ClockProvider clockProvider,
      SecureRandom random,
      byte[] pepper,
      Duration ttl,
      int maxAttempts,
      int rateLimit,
      Duration rateWindow) {
    this.repository = Objects.requireNonNull(repository, "repository");
    this.smsSender = Objects.requireNonNull(smsSender, "smsSender");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.random = Objects.requireNonNull(random, "random");
    Objects.requireNonNull(pepper, "pepper");
    if (pepper.length < 16) {
      throw new IllegalArgumentException("pepper must be at least 16 bytes");
    }
    this.pepper = Arrays.copyOf(pepper, pepper.length);
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
      LOG.info(
          "otp.send rate-limited user={} phone={} count={}", user, maskPhone(phoneE164), recent);
      return new SendResult.RateLimited(recent);
    }

    String code = newCode();
    String hash = hmacHash(code);

    String otpId = UUID.randomUUID().toString();
    repository.save(
        new StoredOtp(otpId, user, phoneE164, hash, 0, maxAttempts, false, now, now.plus(ttl)));
    smsSender.sendOtp(phoneE164, "Your verification code is " + code);
    LOG.info("otp.send issued user={} phone={} otpId={}", user, maskPhone(phoneE164), otpId);
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

    // Increment first to close the TOCTOU window: the returned count is authoritative.
    int newAttempts = repository.incrementAttempts(user, active.otpId());
    if (newAttempts > active.maxAttempts()) {
      return new VerifyResult.AttemptsExceeded();
    }

    String candidateHash = hmacHash(candidate);
    boolean matches =
        MessageDigest.isEqual(
            candidateHash.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            active.hashedCode().getBytes(java.nio.charset.StandardCharsets.UTF_8));

    if (matches) {
      repository.consume(user, active.otpId());
      LOG.info("otp.verify success user={} otpId={}", user, active.otpId());
      return new VerifyResult.Success();
    }
    int remaining = Math.max(0, active.maxAttempts() - newAttempts);
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

  /**
   * Computes {@code HMAC-SHA256(pepper, code)} and returns it Base64-encoded.
   *
   * @param code plaintext code to hash
   * @return Base64 string suitable for storage and constant-time comparison
   */
  private String hmacHash(String code) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(pepper, HMAC_ALGORITHM));
      byte[] digest = mac.doFinal(code.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(digest);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException("HMAC-SHA256 unavailable", e);
    }
  }

  /**
   * Masks a phone number for safe logging, keeping the first digit after {@code +} and the last 4
   * digits of the subscriber number.
   *
   * <p>Examples: {@code +15551234567} → {@code +1***4567}, {@code +441234567890} → {@code
   * +4***7890}. For inputs that are too short to mask meaningfully (fewer than 6 characters total),
   * or that are not recognisable as E.164 (e.g. {@code null}, no {@code +}), returns {@code +***}.
   *
   * @param phone E.164 phone number (expected to start with {@code +})
   * @return masked representation safe for log output
   */
  static String maskPhone(String phone) {
    // Need at least '+' + 1 country digit + at least 1 more digit + 4 suffix = 7 chars minimum
    // for a useful mask. Below that threshold, just return a fixed placeholder.
    if (phone == null
        || phone.length() < 7
        || phone.charAt(0) != '+'
        || !Character.isDigit(phone.charAt(1))) {
      return "+***";
    }
    // Keep the '+' and first digit of the country code only.
    String prefix = phone.substring(0, 2); // e.g. "+1", "+4", "+3"
    String suffix = phone.substring(phone.length() - 4); // last 4 digits
    return prefix + "***" + suffix;
  }
}
