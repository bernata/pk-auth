// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import java.util.Objects;

/**
 * Skeleton {@link EmailSender} for JavaMail / Jakarta Mail. Per brief §3 the implementation is
 * intentionally a stub — host applications add the Jakarta Mail dependency and complete the
 * delivery path.
 */
public final class JavaMailEmailSender implements EmailSender {

  private final String smtpHost;
  private final int smtpPort;
  private final String fromAddress;

  public JavaMailEmailSender(String smtpHost, int smtpPort, String fromAddress) {
    this.smtpHost = Objects.requireNonNull(smtpHost, "smtpHost");
    this.smtpPort = smtpPort;
    this.fromAddress = Objects.requireNonNull(fromAddress, "fromAddress");
  }

  @Override
  public void sendMagicLink(String to, String subject, String body) {
    throw new UnsupportedOperationException(
        "JavaMailEmailSender is a skeleton; host applications must wire Jakarta Mail. host="
            + smtpHost
            + " port="
            + smtpPort
            + " from="
            + fromAddress);
  }
}
