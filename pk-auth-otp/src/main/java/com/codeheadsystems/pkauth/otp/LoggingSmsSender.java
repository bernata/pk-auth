// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Development-only {@link SmsSender} that logs the message instead of delivering an SMS. */
public final class LoggingSmsSender implements SmsSender {

  private static final Logger LOG = LoggerFactory.getLogger(LoggingSmsSender.class);

  public LoggingSmsSender() {}

  @Override
  public void sendOtp(String phoneE164, String message) {
    LOG.info("sms.dev phone={} message={}", phoneE164, message);
  }
}
