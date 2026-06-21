package com.jesusf.paydude.security;

import com.jesusf.paydude.config.properties.CorsProperties;
import com.jesusf.paydude.config.properties.SecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Central Spring Security configuration: two servlet {@link SecurityFilterChain}s, CORS, the
 * authentication infrastructure beans, and the compromised-password checker.
 *
 * <p>The two chains are split by audience and authentication scheme:
 *
 * <ul>
 *   <li><b>Actuator chain</b> ({@code @Order(1)}, matches {@code EndpointRequest.toAnyEndpoint()}):
 *       {@code health}/{@code info} are anonymous (probes, load balancers); everything else —
 *       most notably {@code /actuator/prometheus} — requires {@code ROLE_ADMIN} via <b>HTTP Basic</b>
 *       (RFC 7617). The credential is a dedicated technical account from {@code SecurityProperties},
 *       not a domain user. Newly-exposed endpoints inherit the admin (fail-closed) policy by default.</li>
 *   <li><b>API chain</b> ({@code @Order(2)}, matches everything else): stateless, CSRF-disabled
 *       (authentication is a Bearer header, no cookie to forge), pins an OWASP-aligned
 *       security-header baseline, and runs {@link JwtAuthenticationFilter} ahead of
 *       {@code UsernamePasswordAuthenticationFilter} so a valid token populates the context.</li>
 * </ul>
 *
 * <p>Keeping HTTP Basic confined to the Actuator chain means the API surface stays JWT-only —
 * a {@code Basic} header is never a valid credential for {@code /v1/**}.
 */
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

  private final JwtAuthenticationFilter jwtAuthFilter;
  private final CustomSecurityExceptionHandler customSecurityExceptionHandler;

  /**
   * Filter chain for Spring Boot Actuator, ordered ahead of the API chain so it claims every
   * management endpoint request before the catch-all {@link #securityFilterChain} sees it.
   *
   * <p>{@code health} and {@code info} stay anonymous for orchestrator probes; all other exposed
   * endpoints (including the Prometheus scrape) require {@code ROLE_ADMIN}, authenticated with
   * HTTP Basic. The scraper/operator credential is loaded into an in-memory {@link UserDetailsService}
   * scoped to this chain only, so it is invisible to the JWT-protected API and never touches the
   * {@code users} table. The default {@code BasicAuthenticationEntryPoint} emits the standard
   * {@code WWW-Authenticate: Basic} challenge on a 401 — exactly what a scraper expects.
   *
   * @param http             the {@link HttpSecurity} builder supplied by Spring Security
   * @param securityProps    typed config holding the scraper's Basic-auth credentials
   * @param passwordEncoder  BCrypt encoder used to hash the configured scraper password in memory
   * @return the Actuator filter chain
   * @throws Exception if the chain cannot be built
   */
  @Bean
  @Order(1)
  public SecurityFilterChain actuatorSecurityFilterChain(
      HttpSecurity http,
      SecurityProperties securityProps,
      PasswordEncoder passwordEncoder) throws Exception {

    SecurityProperties.Actuator scraper = securityProps.actuator();
    UserDetailsService scraperDetails = new InMemoryUserDetailsManager(
        User.withUsername(scraper.username())
            .password(passwordEncoder.encode(scraper.password()))
            .roles("ADMIN")
            .build());

    // A local AuthenticationManager scoped to this chain only. Built explicitly (rather than
    // relying on HttpSecurity to assemble one from a shared UserDetailsService) so it authenticates
    // *exclusively* against the in-memory scraper account — it never falls back to the global
    // AuthenticationManager that the API chain uses for DB-backed user login. The scraper principal
    // therefore cannot authenticate against /v1/**, and a /v1 user cannot reach the admin tier.
    DaoAuthenticationProvider scraperProvider = new DaoAuthenticationProvider(scraperDetails);
    scraperProvider.setPasswordEncoder(passwordEncoder);
    AuthenticationManager actuatorAuthManager = new ProviderManager(scraperProvider);

    // Standard RFC 7617 challenge. Set explicitly on both the httpBasic configurer and the
    // exception-handling entry point so an unauthenticated request to the admin tier always gets
    // `WWW-Authenticate: Basic` — not the API chain's Bearer challenge.
    BasicAuthenticationEntryPoint basicEntryPoint = new BasicAuthenticationEntryPoint();
    basicEntryPoint.setRealmName("paydude-actuator");

    http
        .securityMatcher(EndpointRequest.toAnyEndpoint())
        // Public probe tier — health/info arrive unauthenticated by design (Kubernetes
        // liveness/readiness probes, Docker healthchecks, the load balancer).
        .authorizeHttpRequests(req -> req
            .requestMatchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class))
                .permitAll()
            // Admin tier — everything else (Prometheus scrape, metrics, loggers, configprops,
            // env, ...) requires ROLE_ADMIN. No `.excluding(...)` here: any newly-exposed
            // endpoint inherits this policy by default — fail closed, not open.
            .anyRequest().hasRole("ADMIN"))
        .authenticationManager(actuatorAuthManager)
        .httpBasic(basic -> basic.authenticationEntryPoint(basicEntryPoint))
        .exceptionHandling(ex -> ex.authenticationEntryPoint(basicEntryPoint))
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    return http.build();
  }

  /**
   * The API {@link SecurityFilterChain} — the catch-all chain for everything that is not an
   * Actuator endpoint. Stateless and JWT-authenticated.
   *
   * @param http the {@link HttpSecurity} builder supplied by Spring Security
   * @return the configured stateless, JWT-authenticated filter chain
   * @throws Exception if the chain cannot be built
   */
  @Bean
  @Order(2)
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(AbstractHttpConfigurer::disable)
        // CORS is enabled here; the actual allow-list comes from the corsConfigurationSource bean
        // below, which Spring Security picks up by type. Wiring it in the chain (rather than as a
        // standalone CorsFilter) lets Spring Security short-circuit the preflight OPTIONS request
        // before it reaches authorization — a preflight carries no credentials and must not 401.
        .cors(Customizer.withDefaults())
        // HTTP security headers. Spring Security already emits a defensible baseline on every
        // response — X-Content-Type-Options: nosniff, X-Frame-Options: DENY, X-XSS-Protection: 0,
        // and Cache-Control: no-cache, no-store, max-age=0, must-revalidate (the RFC 9111 policy
        // that keeps proxies and browsers from caching account data). We additionally pin three:
        //   - HSTS: tells browsers to only ever reach this host over HTTPS. Spring emits it only
        //     on HTTPS requests, so dev over plain HTTP is unaffected; prod behind TLS gets it.
        //   - Referrer-Policy: no-referrer — an API has no reason to leak its URLs via Referer.
        //   - Content-Security-Policy: frame-ancestors 'none' — the modern, CSP-level equivalent
        //     of X-Frame-Options, refusing to let any page embed our responses in a frame.
        .headers(headers -> headers
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31_536_000))
            .referrerPolicy(referrer -> referrer
                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            .contentSecurityPolicy(csp -> csp
                .policyDirectives("frame-ancestors 'none'"))
        )
        .exceptionHandling(exceptionHandling -> exceptionHandling
            .authenticationEntryPoint(customSecurityExceptionHandler)
            .accessDeniedHandler(customSecurityExceptionHandler)
        )
        // Actuator endpoints are not matched here — they are claimed by the higher-precedence
        // actuatorSecurityFilterChain (@Order(1)) above. This chain governs the API surface only.
        .authorizeHttpRequests(req -> req
            // Exact public token endpoints. Avoid /v1/auth/** so future auth-management routes
            // fail closed unless they are deliberately added here and to JwtAuthenticationFilter.
            .requestMatchers(
                "/v1/auth/register",
                "/v1/auth/login",
                "/v1/auth/refresh",
                "/v1/auth/logout",
                "/v1/auth/mfa/verify"
            ).permitAll()
            .requestMatchers(
                "/v3/api-docs/**",
                "/swagger-ui/**",
                "/swagger-ui.html"
            ).permitAll()
            // Admin tier: the security audit trail (and any future /v1/admin/** route) requires
            // ROLE_ADMIN. This is PayDude's first RBAC-gated API endpoint — until now ROLE_ADMIN
            // guarded only the Actuator chain. A normal user's valid JWT gets 403 here, surfaced via
            // the same CustomSecurityExceptionHandler -> ProblemDetail path as every other error.
            // Kept above the catch-all so it fails closed: /v1/admin/** is never merely authenticated.
            .requestMatchers("/v1/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  /**
   * Keeps {@link JwtAuthenticationFilter} out of the container's own filter chain.
   *
   * <p>Spring Boot auto-registers every {@code Filter} bean with the embedded servlet container.
   * Because the JWT filter is a {@code @Component} (so it can be injected here) <em>and</em> is
   * placed into the API chain via {@code addFilterBefore}, without this registration it would run
   * twice per request — and, worse, the container-level copy (unordered, so last) would also run
   * for requests the API chain never claims: an Actuator probe carrying a stale
   * {@code Authorization: Bearer} header would be rejected with a 401 by the trailing copy
   * <em>after</em> {@link #actuatorSecurityFilterChain} had already permitted it, silently breaking
   * the public probe tier. {@code setEnabled(false)} disables the container registration; the only
   * place the filter executes is the position {@link #securityFilterChain} gives it.
   */
  @Bean
  public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegistration(
      JwtAuthenticationFilter filter) {
    FilterRegistrationBean<JwtAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }

  /**
   * Builds the CORS allow-list from {@link CorsProperties}. Spring Security discovers this bean by
   * type and applies it to the {@code .cors(...)} configured above.
   *
   * <p>{@code allowCredentials} is left {@code false} on purpose: PayDude authenticates with a
   * Bearer token in the {@code Authorization} header, which the JS client sets explicitly — there
   * is no cookie or other ambient credential for the browser to attach, so enabling credentialed
   * CORS would widen the surface for no functional gain.
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource(CorsProperties corsProperties) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(corsProperties.allowedOrigins());
    config.setAllowedMethods(corsProperties.allowedMethods());
    config.setAllowedHeaders(corsProperties.allowedHeaders());
    config.setExposedHeaders(corsProperties.exposedHeaders());
    config.setAllowCredentials(false);
    config.setMaxAge(corsProperties.maxAge());

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  /**
   * Exposes the framework's {@link AuthenticationManager} as a bean so {@code AuthServiceImpl}
   * can drive credential authentication at login.
   *
   * @param config the auto-configured {@link AuthenticationConfiguration}
   * @return the application's {@link AuthenticationManager}
   * @throws Exception if the manager cannot be resolved
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

  /** BCrypt password encoder — hashes passwords at registration and verifies them at login. */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Compromised-password screening backed by the HaveIBeenPwned range API — NIST SP 800-63B
   * §5.1.1.2. The checker uses k-anonymity: only the first five hex characters of the password's
   * SHA-1 digest leave the JVM, never the password itself.
   *
   * <p>Gated by {@code application.security.password.breach-check-enabled} so the {@code test}
   * profile can swap in a no-op decision and keep integration tests off the public network.
   * {@code BreachedPasswordGuard} consumes this bean and layers the fail-open and domain-exception
   * policy on top.
   */
  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker(SecurityProperties securityProperties) {
    if (securityProperties.password().breachCheckEnabled()) {
      return new HaveIBeenPwnedRestApiPasswordChecker();
    }
    return password -> new CompromisedPasswordDecision(false);
  }
}
