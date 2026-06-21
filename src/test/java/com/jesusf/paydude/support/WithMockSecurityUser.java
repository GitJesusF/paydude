package com.jesusf.paydude.support;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Injects the project's {@code SecurityUser} record as the authenticated principal in controller
 * tests. Spring's {@code @WithMockUser} builds a generic {@code User}, which
 * {@code @AuthenticationPrincipal SecurityUser} cannot be cast from (the argument resolves to
 * null). {@code @WithSecurityContext} runs the factory before the test through the
 * TestExecutionListener, so the context is populated even with {@code addFilters = false}.
 */
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockSecurityUserFactory.class)
public @interface WithMockSecurityUser {
  long id() default 1L;
  String email() default "test@test.com";
  String role() default "ROLE_USER";
}
