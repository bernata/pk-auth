// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

/**
 * SPI for sending an email containing a magic link. Per brief §3, pk-auth ships only the SPI plus a
 * logging dev sender and a JavaMail skeleton; production deployments wire a real provider.
 */
public interface EmailSender {

  /** Sends {@code body} to {@code to} with the given {@code subject}. */
  void sendMagicLink(String to, String subject, String body);
}
