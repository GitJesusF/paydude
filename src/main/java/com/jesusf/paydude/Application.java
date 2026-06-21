package com.jesusf.paydude;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Spring Boot entry point for the PayDude API.
 *
 * <p>{@code @ConfigurationPropertiesScan} registers every {@code @ConfigurationProperties}
 * record under {@code config.properties} as a bean, so a new typed-config record is picked
 * up automatically with no extra wiring.
 *
 * <p>Note that {@code @EnableJpaAuditing} deliberately lives on {@code JpaConfig} rather than
 * here — see that class for the rationale.
 */
@SpringBootApplication
@ConfigurationPropertiesScan("com.jesusf.paydude.config.properties")
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

}
