// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import org.jspecify.annotations.Nullable;

/**
 * Thrown by a {@link
 * CredentialRepository#save(com.codeheadsystems.pkauth.credential.CredentialRecord)} implementation
 * when the supplied {@code credentialId} already exists. This is a specific subtype of {@link
 * PkAuthPersistenceException} so that adapters and callers can distinguish a duplicate insert (a
 * {@code 409 Conflict}-class condition) from a generic backend outage (a {@code 503}).
 *
 * <p>The {@link #operation()} is always {@code "credentials.save"}.
 *
 * @since 0.9.1
 */
public final class DuplicateCredentialException extends PkAuthPersistenceException {

  private static final long serialVersionUID = 1L;

  public DuplicateCredentialException(String message, @Nullable Throwable cause) {
    super("credentials.save", message, cause);
  }

  public DuplicateCredentialException(String message) {
    this(message, null);
  }
}
