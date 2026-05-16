// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.resource;

import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps the SPI exception contract (see {@link
 * com.codeheadsystems.pkauth.spi.PkAuthPersistenceException}) to a stable {@code 503 Service
 * Unavailable} JSON response — same wire shape as the Spring and Micronaut adapters. Registered by
 * {@link com.codeheadsystems.pkauth.dropwizard.PkAuthBundle}.
 */
@Provider
public class PkAuthPersistenceExceptionMapper
    implements ExceptionMapper<PkAuthPersistenceException> {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthPersistenceExceptionMapper.class);

  @Override
  public Response toResponse(PkAuthPersistenceException exception) {
    LOG.warn(
        "pkauth.persistence.failure operation={} message={}",
        exception.operation(),
        exception.getMessage(),
        exception);
    Map<String, String> body = new LinkedHashMap<>();
    body.put("error", "persistence_failure");
    body.put("operation", exception.operation());
    return Response.status(503).entity(body).build();
  }
}
