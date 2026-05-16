// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/** Persistent storage for SMS-OTP records (brief §6.5). */
public interface OtpRepository {

  /**
   * Persisted SMS-OTP row.
   *
   * @param otpId opaque server-generated id
   * @param userHandle owning user
   * @param phoneE164 destination phone in E.164 format
   * @param hashedCode HMAC-SHA256(pepper, code) encoded as Base64 of the dispatched code
   * @param attempts how many verification attempts have been made
   * @param maxAttempts threshold above which the code is locked
   * @param consumed whether the code has been verified successfully
   * @param createdAt issuance timestamp (used for rate limiting)
   * @param expiresAt absolute expiry; consumers must treat past-due records as invalid
   */
  record StoredOtp(
      String otpId,
      UserHandle userHandle,
      String phoneE164,
      String hashedCode,
      int attempts,
      int maxAttempts,
      boolean consumed,
      Instant createdAt,
      Instant expiresAt) {
    public StoredOtp {
      Objects.requireNonNull(otpId, "otpId");
      Objects.requireNonNull(userHandle, "userHandle");
      Objects.requireNonNull(phoneE164, "phoneE164");
      Objects.requireNonNull(hashedCode, "hashedCode");
      Objects.requireNonNull(createdAt, "createdAt");
      Objects.requireNonNull(expiresAt, "expiresAt");
      if (attempts < 0) {
        throw new IllegalArgumentException("attempts must be non-negative");
      }
      if (maxAttempts <= 0) {
        throw new IllegalArgumentException("maxAttempts must be positive");
      }
    }
  }

  /** Inserts a freshly issued OTP record. */
  void save(StoredOtp otp);

  /**
   * Returns the most recently issued, non-consumed, non-expired OTP for the given user + phone, if
   * any. Used by {@code OtpService.verify} as the candidate for matching.
   */
  Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164);

  /**
   * Atomically increments the attempts counter for the supplied OTP id and returns the new count.
   * Callers must reject the verification attempt if the returned count exceeds {@code maxAttempts}.
   * The {@code userHandle} addresses the row directly so implementations can avoid full-table
   * scans.
   *
   * @param userHandle owner of the OTP record
   * @param otpId the OTP record to increment
   * @return the attempts value <em>after</em> the increment, or 0 if the row does not exist
   */
  int incrementAttempts(UserHandle userHandle, String otpId);

  /**
   * Marks the supplied OTP id consumed for the given user. Implementations should treat
   * double-consume as a no-op.
   */
  void consume(UserHandle userHandle, String otpId);

  /**
   * Returns how many OTPs were issued for the supplied (user, phone) since {@code since}. Used by
   * the service for rate limiting (brief §6.5 — at most 3 per 15 minutes).
   */
  int countSince(UserHandle userHandle, String phoneE164, Instant since);
}
