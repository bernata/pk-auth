// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import java.util.List;
import java.util.Objects;

/**
 * Outcome of a {@link UserDeletionService#deleteUser com.codeheadsystems.pkauth.api.UserHandle)}
 * call.
 *
 * <p>{@code succeeded + failed = total listeners invoked}. A non-empty {@link #failedListenerNames}
 * indicates one or more listeners threw and were skipped; the user's auth state for those
 * categories is potentially intact and the operator must follow up (retry the deletion or intervene
 * manually). The service has already logged a structured {@code pkauth.user.deletion} event for
 * each failure; this record is for callers that want a programmatic summary.
 *
 * @param succeeded number of listeners that completed without throwing
 * @param failed number of listeners that threw; {@link #failedListenerNames} carries their {@link
 *     UserDeletionListener#name()} values in iteration order
 * @param failedListenerNames names of failed listeners, in the order they were invoked
 * @since 1.1.0
 */
public record UserDeletionResult(int succeeded, int failed, List<String> failedListenerNames) {

  public UserDeletionResult {
    if (succeeded < 0) {
      throw new IllegalArgumentException("succeeded must be non-negative");
    }
    if (failed < 0) {
      throw new IllegalArgumentException("failed must be non-negative");
    }
    Objects.requireNonNull(failedListenerNames, "failedListenerNames");
    failedListenerNames = List.copyOf(failedListenerNames);
    if (failedListenerNames.size() != failed) {
      throw new IllegalArgumentException(
          "failedListenerNames size ("
              + failedListenerNames.size()
              + ") != failed ("
              + failed
              + ")");
    }
  }

  /** Returns {@code true} iff every listener succeeded. */
  public boolean allSucceeded() {
    return failed == 0;
  }
}
