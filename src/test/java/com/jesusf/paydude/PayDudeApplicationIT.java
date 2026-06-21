package com.jesusf.paydude;

import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke integration test that boots the full Spring context against a Testcontainers
 * PostgreSQL instance.
 *
 * <p>The single {@code contextLoads} test is intentionally trivial — its value comes from the
 * setup, not the assertion. Booting the context exercises every {@code @Configuration} class,
 * runs every Flyway migration on a real PostgreSQL database, validates the JPA metamodel
 * against the actual schema, and confirms that bean wiring works end-to-end. A regression in
 * any of these (a typo in a migration, a missing bean, a circular dependency) will fail the
 * test before any other integration test even gets a chance to run.
 */
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
@SpringBootTest
class PayDudeApplicationIT {

  @Test
  @DisplayName("Context loads with full Spring Boot configuration against Testcontainers PostgreSQL")
  void contextLoads() {
    // Deliberately empty: any startup failure (Flyway error, missing bean, circular dependency,
    // unreachable datasource) throws before this method runs and fails the test with the detail.
  }

}