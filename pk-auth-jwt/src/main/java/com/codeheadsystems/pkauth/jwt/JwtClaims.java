// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The pk-auth-specific claim set embedded in every issued JWT. Maps to the JWT body fields
 * described in brief §6.2.
 *
 * @param userHandle the {@code sub} subject (base64url-encoded on the wire)
 * @param method which factor proved possession of this user's account
 * @param credentialId WebAuthn credential id; required iff {@link AuthMethod#PASSKEY}, else null
 * @param amr RFC 8176-compatible authentication-method-reference values
 * @param additionalClaims optional extra claims merged into the JWT body
 */
public record JwtClaims(
    UserHandle userHandle,
    AuthMethod method,
    byte @Nullable [] credentialId,
    List<String> amr,
    @Nullable Map<String, Object> additionalClaims) {

  public JwtClaims {
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(method, "method");
    Objects.requireNonNull(amr, "amr");
    if (method == AuthMethod.PASSKEY && credentialId == null) {
      throw new IllegalArgumentException("credentialId is required when method == PASSKEY");
    }
    if (method != AuthMethod.PASSKEY && credentialId != null) {
      throw new IllegalArgumentException("credentialId must be null when method != PASSKEY");
    }
    if (credentialId != null) {
      credentialId = credentialId.clone();
    }
    amr = List.copyOf(amr);
    if (additionalClaims != null) {
      additionalClaims = Map.copyOf(additionalClaims);
    }
  }

  /** Convenience factory for passkey-issued tokens. */
  public static JwtClaims forPasskey(UserHandle userHandle, byte[] credentialId, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.PASSKEY, credentialId, amr, null);
  }

  /** Convenience factory for backup-code-issued tokens. */
  public static JwtClaims forBackupCode(UserHandle userHandle, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.BACKUP_CODE, null, amr, null);
  }

  /** Convenience factory for magic-link-issued tokens. */
  public static JwtClaims forMagicLink(UserHandle userHandle, List<String> amr) {
    return new JwtClaims(userHandle, AuthMethod.MAGIC_LINK, null, amr, null);
  }

  @Override
  public byte @Nullable [] credentialId() {
    return credentialId == null ? null : credentialId.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof JwtClaims other
        && userHandle.equals(other.userHandle)
        && method == other.method
        && Arrays.equals(credentialId, other.credentialId)
        && amr.equals(other.amr)
        && Objects.equals(additionalClaims, other.additionalClaims);
  }

  @Override
  public int hashCode() {
    return Objects.hash(userHandle, method, Arrays.hashCode(credentialId), amr, additionalClaims);
  }

  @Override
  public String toString() {
    return "JwtClaims[userHandle="
        + userHandle
        + ", method="
        + method
        + ", credentialId="
        + (credentialId == null ? "null" : HexFormat.of().formatHex(credentialId))
        + ", amr="
        + amr
        + "]";
  }
}
