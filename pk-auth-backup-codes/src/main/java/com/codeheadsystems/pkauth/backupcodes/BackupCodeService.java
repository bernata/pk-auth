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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues, verifies, and rotates backup codes per brief §6.3.
 *
 * <p>Each generation produces N (default 10) cryptographically random 10-character alphanumeric
 * codes. Codes are returned to the caller exactly once at generation time; the service then stores
 * Argon2id hashes and never has access to the plaintext again. Verification matches a supplied code
 * against the user's stored hashes and consumes the matching record on success.
 *
 * <p>Verification is rate-limited via a {@link BackupCodeRateLimiter} (default: 5 attempts per user
 * per 60 seconds) to bound the CPU cost of the Argon2id work. Supply a custom {@link
 * BackupCodeRateLimiter} via {@link #BackupCodeService(BackupCodeRepository, ClockProvider,
 * BackupCodeRateLimiter)} to integrate with a shared (Redis/DB-backed) store in multi-instance
 * deployments.
 */
public final class BackupCodeService {

  /** Default count of codes generated per call. */
  public static final int DEFAULT_CODE_COUNT = 10;

  /** Length of each plaintext code in characters. */
  public static final int CODE_LENGTH = 10;

  /** Default maximum verify attempts allowed per user within the rate-limit window. */
  public static final int DEFAULT_RATE_LIMIT = 5;

  /** Default window for the verify rate limit. */
  public static final Duration DEFAULT_RATE_WINDOW = Duration.ofSeconds(60);

  /**
   * A fixed throwaway Argon2id hash used for dummy verifications on consumed code slots so that
   * every loop iteration takes the same wall-clock time regardless of the slot's consumed state.
   * Pre-computed at class-load time with the same cost parameters as the production default
   * (iterations=2, memory=65536, parallelism=1).
   */
  private static final String DUMMY_HASH;

  static {
    Argon2 bootstrap = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    DUMMY_HASH = bootstrap.hash(2, 65_536, 1, "dummy".toCharArray(), StandardCharsets.UTF_8);
  }

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
  private final int rateLimit;
  private final BackupCodeRateLimiter rateLimiter;

  /**
   * Pluggable rate limiter for {@link #verify} calls.
   *
   * <p>The default implementation ({@link InMemoryBackupCodeRateLimiter}) uses an in-process
   * counter that resets after {@link #DEFAULT_RATE_WINDOW}. Production multi-instance deployments
   * SHOULD override with a shared (Redis/DB-backed) implementation so rate limits are not
   * multiplied by the cluster size.
   */
  public interface BackupCodeRateLimiter {
    /**
     * Increments the verify attempt counter for the user and returns the new count.
     *
     * <p>Callers compare the returned count against the configured limit; if the count exceeds the
     * limit the verify attempt is rejected before any Argon2id work is done.
     *
     * @param user the user whose counter to increment
     * @param now the current wall-clock instant (supplied by the service, not re-fetched)
     * @return the new attempt count within the current window
     */
    int countAndIncrement(UserHandle user, Instant now);
  }

  /**
   * Result of a {@link #verify} call.
   *
   * <ul>
   *   <li>{@link Success} — the candidate matched an unconsumed code; the code is now consumed.
   *   <li>{@link NoMatch} — the candidate did not match any unconsumed code.
   *   <li>{@link RateLimited} — the user has exceeded the per-window verify limit; no Argon2id work
   *       was performed. Retry after {@link RateLimited#retryAfterSeconds()} seconds.
   * </ul>
   */
  public sealed interface VerifyResult {
    /** Candidate matched and was consumed. */
    record Success() implements VerifyResult {}

    /** Candidate did not match any unconsumed code. */
    record NoMatch() implements VerifyResult {}

    /**
     * Rate limit exceeded; no Argon2id work was done.
     *
     * @param retryAfterSeconds hint for callers/HTTP 429 Retry-After headers.
     */
    record RateLimited(int retryAfterSeconds) implements VerifyResult {}
  }

  /**
   * Production constructor: uses the default in-process rate limiter (5 verify attempts per user
   * per 60 seconds).
   */
  public BackupCodeService(BackupCodeRepository repository, ClockProvider clockProvider) {
    this(
        repository,
        clockProvider,
        new InMemoryBackupCodeRateLimiter(DEFAULT_RATE_WINDOW),
        new SecureRandom(),
        Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id),
        2,
        65_536,
        1,
        DEFAULT_CODE_COUNT,
        DEFAULT_RATE_LIMIT);
  }

  /**
   * Constructor that allows injection of a custom {@link BackupCodeRateLimiter} while keeping all
   * other parameters at their defaults. Use this in multi-instance deployments where rate limits
   * must be shared across replicas.
   *
   * @param repository persistent store for backup code hashes
   * @param clockProvider wall-clock source for timestamps and rate-window anchoring
   * @param rateLimiter shared rate-limiter implementation; must be thread-safe
   */
  public BackupCodeService(
      BackupCodeRepository repository,
      ClockProvider clockProvider,
      BackupCodeRateLimiter rateLimiter) {
    this(
        repository,
        clockProvider,
        rateLimiter,
        new SecureRandom(),
        Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id),
        2,
        65_536,
        1,
        DEFAULT_CODE_COUNT,
        DEFAULT_RATE_LIMIT);
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
    this(
        repository,
        clockProvider,
        new InMemoryBackupCodeRateLimiter(DEFAULT_RATE_WINDOW),
        random,
        argon2,
        iterations,
        memory,
        parallelism,
        codeCount,
        DEFAULT_RATE_LIMIT);
  }

  /** Full constructor used internally and by tests that need to override the rate limiter too. */
  public BackupCodeService(
      BackupCodeRepository repository,
      ClockProvider clockProvider,
      BackupCodeRateLimiter rateLimiter,
      SecureRandom random,
      Argon2 argon2,
      int iterations,
      int memory,
      int parallelism,
      int codeCount,
      int rateLimit) {
    this.repository = Objects.requireNonNull(repository, "repository");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    this.random = Objects.requireNonNull(random, "random");
    this.argon2 = Objects.requireNonNull(argon2, "argon2");
    this.iterations = iterations;
    this.memory = memory;
    this.parallelism = parallelism;
    this.codeCount = codeCount;
    this.rateLimit = rateLimit;
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

  /**
   * Verifies a candidate plaintext code.
   *
   * <p>On match, the matching code is marked consumed and {@link VerifyResult.Success} is returned.
   * If the per-user rate limit is exceeded, {@link VerifyResult.RateLimited} is returned
   * immediately with no Argon2id work. Otherwise {@link VerifyResult.NoMatch} is returned.
   *
   * <p><strong>Constant-time guarantee:</strong> the method always iterates every stored code row
   * (both consumed and unconsumed). For consumed rows a dummy Argon2id verification is performed
   * against a fixed throwaway hash so that each loop iteration takes approximately the same
   * wall-clock time. This eliminates timing side-channels that would otherwise reveal the number of
   * unconsumed codes or the position of the matching slot.
   */
  public VerifyResult verify(UserHandle user, String candidate) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(candidate, "candidate");

    Instant now = clockProvider.now();
    int count = rateLimiter.countAndIncrement(user, now);
    if (count > rateLimit) {
      LOG.info("backup-codes.verify rate-limited user={} count={}", user, count);
      return new VerifyResult.RateLimited((int) DEFAULT_RATE_WINDOW.toSeconds());
    }

    List<StoredBackupCode> codes = repository.findByUserHandle(user);
    StoredBackupCode matchedCode = null;

    for (StoredBackupCode stored : codes) {
      char[] candidateChars = candidate.toCharArray();
      boolean matches;
      try {
        if (stored.consumed()) {
          // Dummy verify to keep iteration time constant regardless of consumed state.
          argon2.verify(DUMMY_HASH, candidateChars, StandardCharsets.UTF_8);
          matches = false;
        } else {
          matches = argon2.verify(stored.hashedCode(), candidateChars, StandardCharsets.UTF_8);
        }
      } finally {
        argon2.wipeArray(candidateChars);
      }
      // Track first match but do NOT return early — continue to preserve constant time.
      if (matches && matchedCode == null) {
        matchedCode = stored;
      }
    }

    if (matchedCode != null) {
      // The Argon2 verify above is racy with concurrent verifies of the same code: two
      // callers can both observe consumed=false and both pass Argon2 before either writes.
      // The repository.consume contract is the single point of truth — only the caller
      // whose guarded UPDATE / conditional write actually flipped the row from unconsumed
      // to consumed receives true. The loser of the race MUST be reported as a miss so
      // the recovery flow does not mint two JWTs from one code.
      boolean won = repository.consume(user, matchedCode.codeId(), now);
      if (won) {
        LOG.info(
            "backup-codes.verify outcome=success user={} codeId={}", user, matchedCode.codeId());
        return new VerifyResult.Success();
      }
      LOG.info(
          "backup-codes.verify outcome=miss reason=race-lost user={} codeId={}",
          user,
          matchedCode.codeId());
      return new VerifyResult.NoMatch();
    }

    LOG.info("backup-codes.verify outcome=miss user={}", user);
    return new VerifyResult.NoMatch();
  }

  /** Returns how many unconsumed codes the user still has. */
  public int remainingCount(UserHandle user) {
    return (int) repository.findByUserHandle(user).stream().filter(s -> !s.consumed()).count();
  }

  /**
   * Deletes every existing code for the user and issues a fresh set in a single atomic operation
   * via {@link BackupCodeRepository#replaceAll}.
   */
  public List<String> regenerateAll(UserHandle user) {
    Objects.requireNonNull(user, "user");
    List<String> plaintext = new ArrayList<>(codeCount);
    List<StoredBackupCode> records = new ArrayList<>(codeCount);
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
      records.add(new StoredBackupCode(UUID.randomUUID().toString(), user, hash, false, now, null));
    }
    repository.replaceAll(user, records);
    LOG.info("backup-codes.regenerateAll user={} count={}", user, codeCount);
    return List.copyOf(plaintext);
  }

  private String newCode() {
    StringBuilder sb = new StringBuilder(CODE_LENGTH);
    for (int i = 0; i < CODE_LENGTH; i++) {
      sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
    }
    return sb.toString();
  }

  /**
   * Simple in-process rate limiter backed by a {@link ConcurrentHashMap}.
   *
   * <p><strong>FOR DEV / SINGLE-INSTANCE USE ONLY.</strong> Production multi-instance deployments
   * MUST replace this with a shared (Redis/DB-backed) {@link BackupCodeRateLimiter} implementation;
   * otherwise the per-replica limit multiplies by the cluster size.
   */
  public static final class InMemoryBackupCodeRateLimiter implements BackupCodeRateLimiter {

    private static final Logger RL_LOG =
        LoggerFactory.getLogger(InMemoryBackupCodeRateLimiter.class);

    private final long windowMillis;
    private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();

    public InMemoryBackupCodeRateLimiter(Duration window) {
      this.windowMillis = Objects.requireNonNull(window, "window").toMillis();
      RL_LOG.info(
          "backup-codes.rate-limiter InMemoryBackupCodeRateLimiter instantiated — FOR DEV /"
              + " SINGLE-INSTANCE USE ONLY. Production deployments MUST replace this with a"
              + " shared (Redis/DB-backed) BackupCodeRateLimiter.");
    }

    @Override
    public int countAndIncrement(UserHandle user, Instant now) {
      String key = user.toString();
      long nowMs = now.toEpochMilli();
      WindowCounter wc =
          counters.compute(
              key,
              (k, existing) -> {
                if (existing == null || nowMs - existing.windowStart > windowMillis) {
                  return new WindowCounter(nowMs, new AtomicInteger(1));
                }
                existing.count.incrementAndGet();
                return existing;
              });
      return wc.count.get();
    }

    /** Test helper: clears all counters. */
    public void reset() {
      counters.clear();
    }

    private static final class WindowCounter {
      final long windowStart;
      final AtomicInteger count;

      WindowCounter(long windowStart, AtomicInteger count) {
        this.windowStart = windowStart;
        this.count = count;
      }
    }
  }
}
