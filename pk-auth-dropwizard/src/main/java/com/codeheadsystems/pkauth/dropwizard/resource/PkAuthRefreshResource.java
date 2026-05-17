// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.resource;

import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler.Outcome;
import com.codeheadsystems.pkauth.refresh.web.RefreshRequest;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;

/**
 * Refresh endpoint mounted at {@code POST /auth/refresh}. Wraps {@link RefreshHandler}, which is
 * shared with the Spring and Micronaut adapters so rotation logic and error mapping live in one
 * place. Returns {@code 200} on success and {@code 401} with a typed {@code detail} body on any
 * failure.
 *
 * @since 1.1.0
 */
@Path("/auth/refresh")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class PkAuthRefreshResource {

  private final RefreshHandler handler;

  @Inject
  public PkAuthRefreshResource(RefreshHandler handler) {
    this.handler = Objects.requireNonNull(handler, "handler");
  }

  @POST
  public Response refresh(RefreshRequest request) {
    Outcome outcome = handler.handle(request);
    return switch (outcome) {
      case Outcome.Success s -> Response.ok(s.response()).build();
      case Outcome.Failure f ->
          Response.status(Response.Status.UNAUTHORIZED).entity(f.response()).build();
    };
  }
}
