package com.jesusf.paydude.security;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.util.EmailNormalizer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Loads a {@link User} from the database and projects it into a {@link SecurityUser}.
 *
 * <p>Called by {@code DaoAuthenticationProvider} during login (i.e. when
 * {@code AuthenticationManager.authenticate()} runs). After the provider fetches the
 * {@code UserDetails} here, it:
 * <ol>
 *   <li>Compares the raw password against the stored hash using the configured
 *       {@code PasswordEncoder}.</li>
 *   <li>Evaluates the four {@code UserDetails} state checks
 *       ({@code isEnabled}, {@code isAccountNonLocked}, {@code isAccountNonExpired},
 *       {@code isCredentialsNonExpired}).</li>
 *   <li>Throws the matching {@code AuthenticationException} on failure, which the per-concern
 *       security advice translates into the right HTTP status.</li>
 * </ol>
 *
 * <p><b>This service is only invoked at login.</b> Subsequent authenticated requests go through
 * {@code JwtAuthenticationFilter}, which reconstructs the {@code SecurityUser} directly from
 * JWT claims to keep the API stateless and avoid hitting the DB on every request.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  /**
   * Type-safe binding of every {@code application.security.*} property. Replaces the previous
   * dispersed {@code @Value} injection of {@code credentials-expiration-days}; the same value is
   * also consumed by {@code AuthServiceImpl}, so a single source of truth prevents the rotation
   * window enforced on login from drifting away from the one embedded in the JWT.
   *
   * <p>The credential rotation window itself follows NIST SP 800-63B: {@code 0} disables the
   * policy entirely (the prod default), and a positive value computes
   * {@code credentialsExpireAt = passwordChangedAt + N days} so Spring Security rejects the login
   * with {@code CredentialsExpiredException} once the window closes. Enable only when a specific
   * compliance regime (PCI-DSS v3, internal bank audit, certain healthcare or government
   * contexts) requires it.
   */
  private final SecurityProperties securityProperties;

  /**
   * Loads the user with the given email and projects it into a {@link SecurityUser}.
   *
   * @param email the login identifier (this application uses email as the username)
   * @return the {@link SecurityUser} principal for the authentication provider
   * @throws UsernameNotFoundException if no user has that email
   */
  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    String canonicalEmail = EmailNormalizer.normalize(email);

    User user = userRepository.findByEmail(canonicalEmail)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));

    return SecurityUser.fromEntity(user, securityProperties.credentialsExpirationDays());
  }
}
