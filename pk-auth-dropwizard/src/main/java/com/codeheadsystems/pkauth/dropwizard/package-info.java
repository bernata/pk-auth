// SPDX-License-Identifier: MIT
/**
 * Dropwizard 5 adapter for pk-auth. Exposes {@link
 * com.codeheadsystems.pkauth.dropwizard.PkAuthBundle} for host applications and surfaces the four
 * ceremony endpoints under {@code /auth/passkeys}, with optional admin endpoints under {@code
 * /auth/admin} when the {@code pk-auth-admin-api} module is on the classpath.
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.dropwizard;
