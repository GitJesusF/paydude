package com.jesusf.paydude.security;

import com.jesusf.paydude.exception.BusinessException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BreachedPasswordGuard}.
 *
 * <p>The guard is a thin policy wrapper around an injected {@link CompromisedPasswordChecker}.
 * The checker itself (HaveIBeenPwned range API + k-anonymity) is mocked — these tests pin the two
 * decisions the guard adds on top of the raw checker: a compromised password becomes a domain
 * {@link BusinessException}, and a checker failure (API outage) is swallowed so the screening
 * fails open instead of blocking the user.
 */
@ExtendWith(MockitoExtension.class)
class BreachedPasswordGuardTest {

  @Mock
  private CompromisedPasswordChecker compromisedPasswordChecker;

  @InjectMocks
  private BreachedPasswordGuard breachedPasswordGuard;

  @Test
  @DisplayName("passes silently when the checker reports the password is not compromised")
  void shouldPassWhenPasswordNotCompromised() {
    when(compromisedPasswordChecker.check("a-fresh-password"))
        .thenReturn(new CompromisedPasswordDecision(false));

    assertDoesNotThrow(() -> breachedPasswordGuard.assertNotBreached("a-fresh-password"));
  }

  @Test
  @DisplayName("throws BusinessException when the checker reports the password is compromised")
  void shouldThrowWhenPasswordCompromised() {
    // BusinessException (not Spring's CompromisedPasswordException) so the rejection rides the
    // same 409 + ProblemDetail advice as every other domain rule.
    when(compromisedPasswordChecker.check("hunter2"))
        .thenReturn(new CompromisedPasswordDecision(true));

    assertThrows(BusinessException.class,
        () -> breachedPasswordGuard.assertNotBreached("hunter2"));
  }

  @Test
  @DisplayName("fails open — swallows a checker outage so registration is not blocked")
  void shouldFailOpenWhenCheckerThrows() {
    when(compromisedPasswordChecker.check(any()))
        .thenThrow(new RuntimeException("HaveIBeenPwned API unreachable"));

    assertDoesNotThrow(() -> breachedPasswordGuard.assertNotBreached("any-password"));
  }
}