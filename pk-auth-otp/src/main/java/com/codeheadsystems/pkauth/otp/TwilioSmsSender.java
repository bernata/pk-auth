// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import java.util.Objects;

/**
 * Skeleton {@link SmsSender} for Twilio. Per brief §3, pk-auth ships only the SPI — host
 * applications are expected to add the Twilio SDK and complete the implementation. Throwing on call
 * keeps surprises loud.
 */
public final class TwilioSmsSender implements SmsSender {

  private final String accountSid;
  private final String authToken;
  private final String fromNumber;

  public TwilioSmsSender(String accountSid, String authToken, String fromNumber) {
    this.accountSid = Objects.requireNonNull(accountSid, "accountSid");
    this.authToken = Objects.requireNonNull(authToken, "authToken");
    this.fromNumber = Objects.requireNonNull(fromNumber, "fromNumber");
  }

  @Override
  public void sendOtp(String phoneE164, String message) {
    throw new UnsupportedOperationException(
        "TwilioSmsSender is a skeleton; host applications must wire the Twilio SDK. accountSid="
            + accountSid
            + " fromNumber="
            + fromNumber
            + " (authToken length="
            + authToken.length()
            + ")");
  }
}
