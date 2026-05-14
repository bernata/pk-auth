// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

/**
 * SPI for sending an SMS containing an OTP. Implementations live in adapter modules / host
 * applications. The brief intentionally ships only a {@link LoggingSmsSender} for dev and a
 * skeleton {@link TwilioSmsSender}.
 */
public interface SmsSender {

  /** Sends {@code message} to the given {@code phoneE164} number. */
  void sendOtp(String phoneE164, String message);
}
