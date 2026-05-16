// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

/**
 * Thrown by {@code PasskeyAuthenticationService.startRegistration} and {@code startAuthentication}
 * when the configured {@link CeremonyRateLimiter} refuses the call. Adapters map this exception to
 * HTTP {@code 429 Too Many Requests}.
 *
 * <p>This exception type is reserved for the {@code start*} ceremony entrypoints because their
 * response envelopes ({@code StartRegistrationResponse}, {@code StartAuthenticationResponse}) are
 * not sealed result sums and therefore cannot grow a {@code RateLimited} variant without a
 * disruptive API rewrite. The {@code finish*} entrypoints surface the same refusal through the
 * sealed-result variants {@code RegistrationResult.RateLimited} and {@code
 * AssertionResult.RateLimited}.
 *
 * @since 0.9.1
 */
public final class CeremonyRateLimitedException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final String bucket;

  /**
   * Constructs an exception for the given limiter bucket.
   *
   * @param bucket which limiter bucket denied the call ({@code "ip"} or {@code "username"})
   * @since 0.9.1
   */
  public CeremonyRateLimitedException(String bucket) {
    super("ceremony rate-limited (bucket=" + bucket + ")");
    this.bucket = bucket;
  }

  /**
   * Returns the limiter bucket that denied the call ({@code "ip"} or {@code "username"}).
   *
   * @return bucket name
   * @since 0.9.1
   */
  public String bucket() {
    return bucket;
  }
}
