// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import java.util.Objects;

/** Returned from {@code POST /auth/admin/phone/start-verification}. */
public record OtpDispatchResult(String otpId) {
  public OtpDispatchResult {
    Objects.requireNonNull(otpId, "otpId");
  }
}
