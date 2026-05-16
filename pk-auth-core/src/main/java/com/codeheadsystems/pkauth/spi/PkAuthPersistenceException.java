// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import org.jspecify.annotations.Nullable;

/**
 * Unchecked exception thrown by SPI implementations when a host-supplied {@link
 * CredentialRepository}, {@link UserLookup}, {@link ChallengeStore}, {@link BackupCodeRepository},
 * or {@link OtpRepository} backend fails unexpectedly (DB connection drop, throttling,
 * deserialisation error, schema drift, etc.).
 *
 * <p>The contract pk-auth promises to its adapters: any unexpected backend failure inside an SPI
 * call surfaces here. Adapters install a single framework-specific exception handler that maps
 * {@code PkAuthPersistenceException} to a stable {@code 503} response (operational issue, retry
 * possible) with a sanitized body — instead of every adapter accidentally returning a 500 HTML page
 * with a stack trace.
 *
 * <p><b>Implementer contract.</b> Every shipped implementation in this repo (JDBI, DynamoDB,
 * testkit in-memory) MUST wrap the backend's native unexpected exception in this type so adapters
 * can rely on a single catch arm:
 *
 * <ul>
 *   <li>JDBI repos wrap {@code org.jdbi.v3.core.JdbiException} (and any other unchecked exception
 *       from a JDBC driver, e.g. {@code java.sql.SQLException} surfacing as a runtime exception).
 *   <li>DynamoDB repos wrap {@code software.amazon.awssdk.core.exception.SdkException} (network
 *       failures, throttling, schema drift). {@code ConditionalCheckFailedException} that is part
 *       of a documented false-return / boolean-result path (e.g. {@code consume} or {@code
 *       save}-duplicate-detection) is NOT wrapped — it's an expected control-flow signal, not a
 *       backend outage.
 *   <li>Testkit in-memory repos have no real backend, but per this contract MUST still wrap any
 *       unexpected {@link RuntimeException} that escapes (programming error, NPE from a malformed
 *       record) so the adapter exception mappers fire uniformly in unit / integration tests.
 * </ul>
 *
 * <p><b>Operation identifier.</b> The {@link #operation()} string MUST be {@code
 * "<repository>.<method>"} (e.g. {@code "credentials.save"}, {@code "otp.incrementAttempts"}) so
 * operators can pinpoint the failing call from a single log line.
 *
 * <p>Adapters MUST NOT catch this and silently swallow it — the host needs to know that persistence
 * is degraded.
 *
 * <p>The dedicated subtype {@link DuplicateCredentialException} signals the specific duplicate-row
 * insert case so adapters and host code can map it to a {@code 409 Conflict} instead of a generic
 * {@code 503}.
 *
 * @see com.codeheadsystems.pkauth.spi
 * @since 0.9.1
 */
public sealed class PkAuthPersistenceException extends RuntimeException
    permits DuplicateCredentialException {

  private static final long serialVersionUID = 1L;

  /**
   * A short operator-friendly identifier of the failing operation, e.g. {@code credentials.save}.
   */
  @SuppressWarnings("serial") // String is Serializable; final field — no risk.
  private final String operation;

  public PkAuthPersistenceException(String operation, String message, @Nullable Throwable cause) {
    super(message, cause);
    this.operation = operation;
  }

  public PkAuthPersistenceException(String operation, String message) {
    this(operation, message, null);
  }

  public String operation() {
    return operation;
  }
}
