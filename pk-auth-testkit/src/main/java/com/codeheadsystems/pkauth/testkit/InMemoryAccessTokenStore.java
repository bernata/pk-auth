// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link AccessTokenStore} for unit tests, dev-mode boots, and parity tests. Backed by a
 * {@link ConcurrentHashMap}.
 *
 * @since 1.1.0
 */
public final class InMemoryAccessTokenStore implements AccessTokenStore {

  private final Map<String, Row> byJti = new ConcurrentHashMap<>();

  public InMemoryAccessTokenStore() {}

  @Override
  public void record(
      String jti,
      UserHandle userHandle,
      String audience,
      Optional<String> deviceId,
      Instant issuedAt,
      Instant expiresAt) {
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    byJti.put(jti, new Row(jti, userHandle, audience, deviceId.orElse(null), issuedAt, expiresAt));
  }

  @Override
  public boolean exists(String jti) {
    return jti != null && byJti.containsKey(jti);
  }

  @Override
  public boolean delete(String jti) {
    return byJti.remove(jti) != null;
  }

  @Override
  public int deleteAllForUser(UserHandle userHandle) {
    int[] removed = {0};
    byJti
        .entrySet()
        .removeIf(
            e -> {
              if (e.getValue().userHandle.equals(userHandle)) {
                removed[0]++;
                return true;
              }
              return false;
            });
    return removed[0];
  }

  @Override
  public int deleteExpiredBefore(Instant before) {
    int[] removed = {0};
    byJti
        .entrySet()
        .removeIf(
            e -> {
              if (e.getValue().expiresAt.isBefore(before)) {
                removed[0]++;
                return true;
              }
              return false;
            });
    return removed[0];
  }

  /** Visible for testing. */
  public int size() {
    return byJti.size();
  }

  private record Row(
      String jti,
      UserHandle userHandle,
      String audience,
      String deviceId,
      Instant issuedAt,
      Instant expiresAt) {}
}
