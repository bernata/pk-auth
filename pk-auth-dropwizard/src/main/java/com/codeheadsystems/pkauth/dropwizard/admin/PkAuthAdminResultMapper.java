// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

import com.codeheadsystems.pkauth.admin.AdminResponseMapper;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper.AdminResponse;
import com.codeheadsystems.pkauth.admin.AdminResult;
import jakarta.ws.rs.core.Response;

/**
 * Dropwizard binding for {@link AdminResponseMapper}: converts the framework-neutral {@link
 * AdminResponse} into a Jersey {@link Response}. All status codes, headers, and body shapes are
 * owned by {@link AdminResponseMapper} so they stay byte-for-byte identical across the Spring,
 * Dropwizard, and Micronaut adapters.
 *
 * @since 0.9.1
 */
public final class PkAuthAdminResultMapper {

  private PkAuthAdminResultMapper() {}

  /** Builds a Jersey {@link Response} from {@code result}. */
  public static <T> Response toResponse(AdminResult<T> result) {
    return toResponse(AdminResponseMapper.toResponse(result));
  }

  /** Builds a Jersey {@link Response} from {@code response}. */
  public static Response toResponse(AdminResponse response) {
    Response.ResponseBuilder builder = Response.status(response.status());
    response.headers().forEach(builder::header);
    if (response.body() != null) {
      builder.entity(response.body());
    }
    return builder.build();
  }
}
