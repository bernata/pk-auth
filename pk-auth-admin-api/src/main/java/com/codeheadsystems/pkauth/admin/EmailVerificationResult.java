// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import java.util.Objects;

/**
 * Wire-shape response for {@code POST /auth/admin/email/complete-verification} — JSON {@code
 * {"userHandle": "<base64url>"}}. Promoted out of the per-adapter controllers so every adapter
 * emits the identical envelope; before promotion the Spring adapter wrapped the handle in {@code
 * Map.of(...)} while Dropwizard and Micronaut returned the bare {@code UserHandle} value (which
 * serialises to a string but with no enclosing object).
 *
 * @param userHandle base64url-encoded (RFC 4648 §5, no padding) {@code UserHandle.value()} bytes
 * @since 0.9.1
 */
public record EmailVerificationResult(String userHandle) {

  /** Defensive copy: the wire field must always be present and non-blank. */
  public EmailVerificationResult {
    Objects.requireNonNull(userHandle, "userHandle");
  }
}
