// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Wiring tests for {@link AccessTokenStore} integration with the issuer and validator. */
class AccessTokenStoreIntegrationTest {

  private static final Instant NOW = Instant.parse("2026-05-16T12:00:00Z");
  private static final String ISSUER = "https://pkauth.example.com";
  private static final String AUDIENCE = "api.example.com";

  @Test
  void noopStoreAcceptsEveryJtiAndPersistsNothing() {
    AccessTokenStore store = AccessTokenStore.noop();
    assertThat(store.exists("anything")).isTrue();
    assertThat(store.delete("anything")).isFalse();
    assertThat(store.deleteAllForUser(UserHandle.of(new byte[] {1}))).isZero();
    assertThat(store.deleteExpiredBefore(NOW)).isZero();
    // record is a true no-op — accepts any inputs without throwing.
    store.record(
        "jti-X",
        UserHandle.of(new byte[] {1}),
        AUDIENCE,
        Optional.empty(),
        NOW,
        NOW.plusSeconds(60));
    assertThat(store.toString()).contains("noop");
  }

  @Test
  void issuedTokenIsRecordedInStatefulStore() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    RecordingStore store = new RecordingStore();

    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW), store);
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {7}), List.of("user")));

    assertThat(store.recorded).hasSize(1);
    RecordingStore.Row row = store.recorded.values().iterator().next();
    assertThat(row.jti).isNotBlank();
    assertThat(row.audience).isEqualTo(AUDIENCE);
    assertThat(row.userHandle).isEqualTo(UserHandle.of(new byte[] {7}));
    assertThat(token).isNotBlank();
  }

  @Test
  void validatorRejectsJtiAbsentFromStatefulStore() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);

    // Issue with a recording store (so record() fires) but validate against an empty store.
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(config, keyset, fixedClock(NOW), new RecordingStore());
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(
            config, keyset, fixedClock(NOW), RevocationCheck.allow(), new EmptyStore());

    JwtVerificationResult result = validator.validate(token);
    assertThat(result).isInstanceOf(JwtVerificationResult.Revoked.class);
  }

  @Test
  void validatorAcceptsJtiPresentInStatefulStore() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    RecordingStore store = new RecordingStore();

    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW), store);
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {2}), List.of("user")));

    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(config, keyset, fixedClock(NOW), RevocationCheck.allow(), store);
    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.Success.class);
  }

  @Test
  void deletionListenerForwardsToStore() {
    RecordingStore store = new RecordingStore();
    store.recorded.put("a", new RecordingStore.Row("a", UserHandle.of(new byte[] {9}), AUDIENCE));
    store.recorded.put("b", new RecordingStore.Row("b", UserHandle.of(new byte[] {9}), AUDIENCE));
    store.recorded.put("c", new RecordingStore.Row("c", UserHandle.of(new byte[] {8}), AUDIENCE));

    AccessTokenStoreDeletionListener listener = new AccessTokenStoreDeletionListener(store);
    listener.onUserDeleted(UserHandle.of(new byte[] {9}));

    assertThat(store.recorded.keySet()).containsExactly("c");
  }

  // -- Helpers ----------------------------------------------------------------------------

  private static byte[] randomBytes(int len) {
    byte[] out = new byte[len];
    new SecureRandom().nextBytes(out);
    return out;
  }

  private static ClockProvider fixedClock(Instant instant) {
    return ClockProvider.fromClock(Clock.fixed(instant, ZoneOffset.UTC));
  }

  /** Records every {@code record(...)} call in an ordered map; supports lookup and bulk delete. */
  private static final class RecordingStore implements AccessTokenStore {
    record Row(String jti, UserHandle userHandle, String audience) {}

    final Map<String, Row> recorded = new HashMap<>();

    @Override
    public void record(
        String jti,
        UserHandle userHandle,
        String audience,
        Optional<String> deviceId,
        Instant issuedAt,
        Instant expiresAt) {
      recorded.put(jti, new Row(jti, userHandle, audience));
    }

    @Override
    public boolean exists(String jti) {
      return recorded.containsKey(jti);
    }

    @Override
    public boolean delete(String jti) {
      return recorded.remove(jti) != null;
    }

    @Override
    public int deleteAllForUser(UserHandle userHandle) {
      List<String> toRemove = new ArrayList<>();
      for (Row r : recorded.values()) {
        if (r.userHandle.equals(userHandle)) {
          toRemove.add(r.jti);
        }
      }
      toRemove.forEach(recorded::remove);
      return toRemove.size();
    }

    @Override
    public int deleteExpiredBefore(Instant before) {
      return 0;
    }
  }

  /** Store that never sees any record but is queried by the validator. */
  private static final class EmptyStore implements AccessTokenStore {
    @Override
    public void record(
        String jti,
        UserHandle userHandle,
        String audience,
        Optional<String> deviceId,
        Instant issuedAt,
        Instant expiresAt) {}

    @Override
    public boolean exists(String jti) {
      return false;
    }

    @Override
    public boolean delete(String jti) {
      return false;
    }

    @Override
    public int deleteAllForUser(UserHandle userHandle) {
      return 0;
    }

    @Override
    public int deleteExpiredBefore(Instant before) {
      return 0;
    }
  }

  @SuppressWarnings("unused")
  private static Set<String> dummy() {
    return Set.of();
  }
}
