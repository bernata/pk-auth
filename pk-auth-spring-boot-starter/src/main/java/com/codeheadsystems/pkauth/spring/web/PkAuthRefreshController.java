// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.web;

import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler.Outcome;
import com.codeheadsystems.pkauth.refresh.web.RefreshRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mounts the refresh endpoint at {@code POST /auth/refresh}. Delegates to {@link RefreshHandler},
 * which is shared with the Dropwizard and Micronaut adapters so rotation logic and error mapping
 * live in one place. Returns {@code 200} with the new refresh + access tokens on success and {@code
 * 401} with a typed {@code detail} body on any failure.
 *
 * @since 1.1.0
 */
@RestController
public class PkAuthRefreshController {

  private final RefreshHandler handler;

  public PkAuthRefreshController(RefreshHandler handler) {
    this.handler = handler;
  }

  @PostMapping("/auth/refresh")
  public ResponseEntity<Object> refresh(@RequestBody(required = false) RefreshRequest request) {
    Outcome outcome = handler.handle(request);
    return switch (outcome) {
      case Outcome.Success s -> ResponseEntity.ok(s.response());
      case Outcome.Failure f -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(f.response());
    };
  }
}
