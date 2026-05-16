// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.Nullable;

/**
 * Caffeine-backed {@link ChallengeStore}. {@code takeOnce} is single-use via {@code
 * Cache#asMap().remove}, which is atomic under Caffeine's contract.
 */
public final class InMemoryChallengeStore implements ChallengeStore {

  private final Cache<ChallengeId, Entry> cache;

  public InMemoryChallengeStore() {
    this.cache =
        Caffeine.newBuilder()
            .expireAfter(
                new Expiry<ChallengeId, Entry>() {
                  @Override
                  public long expireAfterCreate(ChallengeId key, Entry value, long currentTime) {
                    return value.ttl.toNanos();
                  }

                  @Override
                  public long expireAfterUpdate(
                      ChallengeId key, Entry value, long currentTime, long currentDuration) {
                    return currentDuration;
                  }

                  @Override
                  public long expireAfterRead(
                      ChallengeId key, Entry value, long currentTime, long currentDuration) {
                    return currentDuration;
                  }
                })
            .build();
  }

  @Override
  public void put(ChallengeId id, ChallengeRecord record, Duration ttl) {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(record, "record");
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be strictly positive, got " + ttl);
    }
    cache.put(id, new Entry(record, ttl));
  }

  @Override
  public Optional<ChallengeRecord> takeOnce(ChallengeId id) {
    @Nullable Entry removed = cache.asMap().remove(id);
    return Optional.ofNullable(removed).map(e -> e.record);
  }

  /** Exposed for tests that want to inspect the in-memory state. */
  public long size() {
    cache.cleanUp();
    return cache.estimatedSize();
  }

  /** Test helper to force expiry of a stored challenge without waiting. */
  public void invalidate(ChallengeId id) {
    cache.invalidate(id);
  }

  /** Test helper to clear all stored challenges. */
  public void clear() {
    cache.invalidateAll();
  }

  /** Test helper to wait for cache cleanup (Caffeine evicts lazily). */
  public void awaitCleanup() {
    cache.cleanUp();
    try {
      TimeUnit.MILLISECONDS.sleep(1);
    } catch (InterruptedException ignored) {
      Thread.currentThread().interrupt();
    }
  }

  private record Entry(ChallengeRecord record, Duration ttl) {}
}
