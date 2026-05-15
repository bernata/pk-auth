// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.micronaut;

import io.micronaut.runtime.Micronaut;

/** Entry point for the Micronaut demo application. */
public final class MicronautDemoApplication {

  private MicronautDemoApplication() {}

  public static void main(String[] args) {
    Micronaut.run(MicronautDemoApplication.class, args);
  }
}
