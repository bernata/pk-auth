// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.json.Base64Url;
import java.security.SecureRandom;

/**
 * Produces challenge bytes and the matching {@link ChallengeId}. The id is the base64url-encoded
 * challenge so the server can rebuild it from the client's {@code clientDataJSON} at finish time
 * (the client also sends it explicitly as a cross-check).
 *
 * <p>32 random bytes matches the WebAuthn level 3 recommendation of "at least 16 bytes" with
 * comfortable headroom.
 */
public final class ChallengeGenerator {

  static final int CHALLENGE_BYTES = 32;

  private final SecureRandom random;

  public ChallengeGenerator() {
    this(new SecureRandom());
  }

  /** Test seam: inject a {@link SecureRandom} for deterministic challenge generation in tests. */
  public ChallengeGenerator(SecureRandom random) {
    this.random = random;
  }

  /** Generates {@value #CHALLENGE_BYTES} random bytes for use as a WebAuthn challenge. */
  public byte[] generate() {
    byte[] challenge = new byte[CHALLENGE_BYTES];
    random.nextBytes(challenge);
    return challenge;
  }

  /** Derives a {@link ChallengeId} from challenge bytes. */
  public static ChallengeId idOf(byte[] challenge) {
    return new ChallengeId(Base64Url.encode(challenge));
  }
}
