// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link OtpRepository}. */
public final class InMemoryOtpRepository implements OtpRepository {

  private final Map<String, StoredOtp> byId = new ConcurrentHashMap<>();

  public InMemoryOtpRepository() {}

  @Override
  public void save(StoredOtp otp) {
    byId.put(otp.otpId(), otp);
  }

  @Override
  public Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164) {
    return byId.values().stream()
        .filter(o -> o.userHandle().equals(userHandle))
        .filter(o -> o.phoneE164().equals(phoneE164))
        .filter(o -> !o.consumed())
        .max(Comparator.comparing(StoredOtp::createdAt));
  }

  @Override
  public int incrementAttempts(UserHandle userHandle, String otpId) {
    // Use an array to capture the new attempts count from inside the lambda.
    int[] newAttempts = {0};
    byId.computeIfPresent(
        otpId,
        (k, existing) -> {
          if (!existing.userHandle().equals(userHandle)) {
            return existing;
          }
          int updated = existing.attempts() + 1;
          newAttempts[0] = updated;
          return new StoredOtp(
              existing.otpId(),
              existing.userHandle(),
              existing.phoneE164(),
              existing.hashedCode(),
              updated,
              existing.maxAttempts(),
              existing.consumed(),
              existing.createdAt(),
              existing.expiresAt());
        });
    return newAttempts[0];
  }

  @Override
  public void consume(UserHandle userHandle, String otpId) {
    byId.computeIfPresent(
        otpId,
        (k, existing) -> {
          if (!existing.userHandle().equals(userHandle)) {
            return existing;
          }
          return new StoredOtp(
              existing.otpId(),
              existing.userHandle(),
              existing.phoneE164(),
              existing.hashedCode(),
              existing.attempts(),
              existing.maxAttempts(),
              true,
              existing.createdAt(),
              existing.expiresAt());
        });
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    return (int)
        byId.values().stream()
            .filter(o -> o.userHandle().equals(userHandle))
            .filter(o -> o.phoneE164().equals(phoneE164))
            .filter(o -> !o.createdAt().isBefore(since))
            .count();
  }
}
