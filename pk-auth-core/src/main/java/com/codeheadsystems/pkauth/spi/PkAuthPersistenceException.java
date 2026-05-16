// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import org.jspecify.annotations.Nullable;

/**
 * Unchecked exception that SPI implementations may throw — or that callers may catch — when a
 * host-supplied {@link CredentialRepository}, {@link UserLookup}, {@link ChallengeStore}, {@link
 * BackupCodeRepository}, or {@link OtpRepository} backend fails to satisfy the operation (DB
 * connection drop, throttling, deserialisation error, schema drift, etc.).
 *
 * <p>The contract pk-auth promises to its adapters: any unexpected backend failure inside an SPI
 * call surfaces here. Adapters install a single framework-specific exception handler that maps
 * {@code PkAuthPersistenceException} to a stable {@code 503} response (operational issue, retry
 * possible) with a sanitized body — instead of every adapter accidentally returning a 500 HTML page
 * with a stack trace.
 *
 * <p>SPI implementers SHOULD wrap their backend's native exception (e.g. {@code SQLException},
 * {@code DynamoDbException}) in this type so adapters can rely on a single catch arm. The pk-auth
 * persistence modules in this repo do so. Adapters MUST NOT catch this and silently swallow it —
 * the host needs to know that persistence is degraded.
 *
 * @see com.codeheadsystems.pkauth.spi
 */
public final class PkAuthPersistenceException extends RuntimeException {

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
