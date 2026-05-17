// SPDX-License-Identifier: MIT

/**
 * Framework-neutral construction recipes for pk-auth's core services. Adapter modules (Spring,
 * Dropwizard, Micronaut) call into {@link com.codeheadsystems.pkauth.composition.PkAuthComposition}
 * from their per-framework DI providers so the wiring graph is named in one place rather than
 * duplicated three times.
 *
 * <p>Lives in {@code pk-auth-jwt} (rather than {@code pk-auth-core}) because the orchestrator
 * helper references both core ceremony types and JWT types; {@code pk-auth-jwt} already depends on
 * {@code pk-auth-core}, so the import direction stays clean.
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.composition;
