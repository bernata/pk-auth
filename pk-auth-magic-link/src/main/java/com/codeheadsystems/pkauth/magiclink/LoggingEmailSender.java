// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Development-only {@link EmailSender} that logs the email instead of delivering it. */
public final class LoggingEmailSender implements EmailSender {

  private static final Logger LOG = LoggerFactory.getLogger(LoggingEmailSender.class);

  public LoggingEmailSender() {}

  @Override
  public void sendMagicLink(String to, String subject, String body) {
    // Do not log the body — it contains the plaintext magic-link token.
    LOG.info(
        "email.dev to={} subject={} bodyLength={}",
        to,
        subject,
        (body == null ? 0 : body.length()));
  }
}
