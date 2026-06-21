package com.jesusf.paydude.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Enables JPA auditing, which populates the {@code @CreatedDate} and {@code @LastModifiedDate}
 * fields on entities.
 *
 * <p>{@code @EnableJpaAuditing} is kept here rather than on {@code Application} on purpose. When
 * placed on the main application class it is also picked up by {@code @WebMvcTest} slices, which
 * do not bootstrap JPA — and auditing then fails the slice with "JPA metamodel must not be
 * empty". Isolating it in a dedicated {@code @Configuration} keeps the web-layer tests bootable.
 */
@Configuration
@EnableJpaAuditing
public class JpaConfig {
}
