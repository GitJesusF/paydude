package com.jesusf.paydude.config;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.config.web.ApiV2;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerTypePredicate;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Spring MVC configuration — currently the home of URI-path API versioning.
 *
 * <p>Rather than hard-coding {@code /v1} into every {@code @RequestMapping}, controllers carry a
 * marker annotation ({@link ApiV1} / {@link ApiV2}) and the prefix is applied centrally here.
 * Adding a new version is a new marker plus one line, and the existing controllers are untouched.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

  /**
   * Prepends a version prefix to every controller annotated with the matching marker:
   * {@code /v1} for {@link ApiV1}, {@code /v2} for {@link ApiV2}.
   *
   * @param configurer the path-match configurer supplied by Spring MVC
   */
  @Override
  public void configurePathMatch(PathMatchConfigurer configurer) {
    configurer.addPathPrefix("/v1", HandlerTypePredicate.forAnnotation(ApiV1.class));
    configurer.addPathPrefix("/v2", HandlerTypePredicate.forAnnotation(ApiV2.class));
  }
}
