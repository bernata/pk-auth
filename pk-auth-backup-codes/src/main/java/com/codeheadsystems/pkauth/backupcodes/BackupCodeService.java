// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.backupcodes;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository.StoredBackupCode;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues, verifies, and rotates backup codes per brief §6.3.
 *
 * <p>Each generation produces N (default 10) cryptographically random 10-character alphanumeric
 * codes. Codes are returned to the caller exactly once at generation time; the service then stores
 * Argon2id hashes and never has access to the plaintext again. Verification matches a supplied code
 * against the user's stored hashes and consumes the matching record on success.
 */
public final class BackupCodeService {

  /** Default count of codes generated per call. */
  public static final int DEFAULT_CODE_COUNT = 10;

  /** Length of each plaintext code in characters. */
  public static final int CODE_LENGTH = 10;

  private static final char[] ALPHABET =
      "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray(); // ambiguous chars omitted

  private static final Logger LOG = LoggerFactory.getLogger(BackupCodeService.class);

  private final BackupCodeRepository repository;
  private final ClockProvider clockProvider;
  private final SecureRandom random;
  private final Argon2 argon2;
  private final int iterations;
  private final int memory;
  private final int parallelism;
  private final int codeCount;

  public BackupCodeService(BackupCodeRepository repository, ClockProvider clockProvider) {
    this(
        repository,
        clockProvider,
        new SecureRandom(),
        Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id),
        2,
        65_536,
        1,
        DEFAULT_CODE_COUNT);
  }

  /** Test seam allowing override of Argon2id parameters and the random source. */
  public BackupCodeService(
      BackupCodeRepository repository,
      ClockProvider clockProvider,
      SecureRandom random,
      Argon2 argon2,
      int iterations,
      int memory,
      int parallelism,
      int codeCount) {
    this.repository = Objects.requireNonNull(repository, "repository");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.random = Objects.requireNonNull(random, "random");
    this.argon2 = Objects.requireNonNull(argon2, "argon2");
    this.iterations = iterations;
    this.memory = memory;
    this.parallelism = parallelism;
    this.codeCount = codeCount;
  }

  /**
   * Generates a fresh set of {@code codeCount} backup codes. The plaintext list is returned to the
   * caller exactly once; the service persists only the hashes.
   */
  public List<String> generate(UserHandle user) {
    Objects.requireNonNull(user, "user");
    List<String> plaintext = new ArrayList<>(codeCount);
    var now = clockProvider.now();
    for (int i = 0; i < codeCount; i++) {
      String code = newCode();
      plaintext.add(code);
      char[] codeChars = code.toCharArray();
      String hash;
      try {
        hash = argon2.hash(iterations, memory, parallelism, codeChars, StandardCharsets.UTF_8);
      } finally {
        argon2.wipeArray(codeChars);
      }
      repository.save(
          new StoredBackupCode(UUID.randomUUID().toString(), user, hash, false, now, null));
    }
    LOG.info("backup-codes.generate user={} count={}", user, codeCount);
    return List.copyOf(plaintext);
  }

  /** Verifies a candidate plaintext code; on match, marks it consumed and returns true. */
  public boolean verify(UserHandle user, String candidate) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(candidate, "candidate");
    for (StoredBackupCode stored : repository.findByUserHandle(user)) {
      if (stored.consumed()) {
        continue;
      }
      char[] candidateChars = candidate.toCharArray();
      boolean matches;
      try {
        matches = argon2.verify(stored.hashedCode(), candidateChars, StandardCharsets.UTF_8);
      } finally {
        argon2.wipeArray(candidateChars);
      }
      if (matches) {
        repository.consume(stored.codeId(), clockProvider.now());
        LOG.info("backup-codes.verify outcome=success user={} codeId={}", user, stored.codeId());
        return true;
      }
    }
    LOG.info("backup-codes.verify outcome=miss user={}", user);
    return false;
  }

  /** Returns how many unconsumed codes the user still has. */
  public int remainingCount(UserHandle user) {
    return (int) repository.findByUserHandle(user).stream().filter(s -> !s.consumed()).count();
  }

  /** Deletes every existing code for the user and issues a fresh set. */
  public List<String> regenerateAll(UserHandle user) {
    repository.deleteByUserHandle(user);
    return generate(user);
  }

  private String newCode() {
    StringBuilder sb = new StringBuilder(CODE_LENGTH);
    for (int i = 0; i < CODE_LENGTH; i++) {
      sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
    }
    return sb.toString();
  }
}
