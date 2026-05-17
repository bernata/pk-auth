// SPDX-License-Identifier: MIT

/** pk-auth testkit module. */
module com.codeheadsystems.pkauth.testkit {
  requires transitive com.codeheadsystems.pkauth.core;
  requires transitive com.codeheadsystems.pkauth.jwt;
  requires transitive com.webauthn4j.core;
  requires transitive tools.jackson.databind;
  requires transitive com.fasterxml.jackson.annotation;
  requires com.github.benmanes.caffeine;
  requires org.slf4j;
  requires org.jspecify;
  requires transitive org.assertj.core;

  exports com.codeheadsystems.pkauth.testkit;
}
