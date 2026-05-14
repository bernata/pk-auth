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
  public void incrementAttempts(String otpId) {
    byId.computeIfPresent(
        otpId,
        (k, existing) ->
            new StoredOtp(
                existing.otpId(),
                existing.userHandle(),
                existing.phoneE164(),
                existing.hashedCode(),
                existing.attempts() + 1,
                existing.maxAttempts(),
                existing.consumed(),
                existing.createdAt(),
                existing.expiresAt()));
  }

  @Override
  public void consume(String otpId) {
    byId.computeIfPresent(
        otpId,
        (k, existing) ->
            new StoredOtp(
                existing.otpId(),
                existing.userHandle(),
                existing.phoneE164(),
                existing.hashedCode(),
                existing.attempts(),
                existing.maxAttempts(),
                true,
                existing.createdAt(),
                existing.expiresAt()));
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
