// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

/**
 * The authentication factor that produced the JWT. Wire spellings (lowercase, hyphen-separated) are
 * part of the public API and match the brief §6.2 contract.
 */
public enum AuthMethod {
  PASSKEY("passkey"),
  BACKUP_CODE("backup-code"),
  MAGIC_LINK("magic-link");

  private final String wireValue;

  AuthMethod(String wireValue) {
    this.wireValue = wireValue;
  }

  public String wireValue() {
    return wireValue;
  }

  /** Parse a wire value back into an enum constant. Returns null on unknown input. */
  public static AuthMethod fromWireValue(String value) {
    for (AuthMethod m : values()) {
      if (m.wireValue.equals(value)) {
        return m;
      }
    }
    throw new IllegalArgumentException("Unknown pkauth.method wire value: " + value);
  }
}
