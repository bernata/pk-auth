// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.admin;

import com.codeheadsystems.pkauth.admin.AdminResponseMapper;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper.AdminResponse;
import com.codeheadsystems.pkauth.admin.AdminResult;
import org.springframework.http.ResponseEntity;

/**
 * Spring binding for {@link AdminResponseMapper}: converts the framework-neutral {@link
 * AdminResponse} into a {@link ResponseEntity}. All status codes, headers, and body shapes are
 * owned by {@link AdminResponseMapper} so they stay byte-for-byte identical across the Spring,
 * Dropwizard, and Micronaut adapters.
 *
 * @since 0.9.1
 */
public final class PkAuthAdminResultMapper {

  private PkAuthAdminResultMapper() {}

  /** Converts any {@link AdminResult} to a {@link ResponseEntity}. */
  public static <T> ResponseEntity<Object> toResponse(AdminResult<T> result) {
    return toResponseEntity(AdminResponseMapper.toResponse(result));
  }

  /** Converts a {@link AdminResponse} to a {@link ResponseEntity}. */
  public static ResponseEntity<Object> toResponseEntity(AdminResponse response) {
    ResponseEntity.BodyBuilder builder = ResponseEntity.status(response.status());
    response.headers().forEach(builder::header);
    if (response.body() == null) {
      return builder.build();
    }
    return builder.body(response.body());
  }
}
