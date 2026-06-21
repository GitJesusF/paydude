package com.jesusf.paydude.listener;

import com.jesusf.paydude.event.UserRegisteredEvent;
import com.jesusf.paydude.service.AccountService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link AccountEventListener}.
 *
 * <p>The listener wires registration to default-account creation. In production it runs at
 * {@code TransactionPhase.BEFORE_COMMIT} so a failure in account creation also rolls back the
 * user registration. Here we only assert the delegation contract — that the {@link AccountService}
 * is invoked with the right user id. The {@code BEFORE_COMMIT} semantics are exercised by the
 * integration test, where a real transaction can be rolled back; in a unit test there is no
 * transaction to phase against.
 */
@ExtendWith(MockitoExtension.class)
class AccountEventListenerTest {

  @Mock
  private AccountService accountService;

  @InjectMocks
  private AccountEventListener listener;

  @Test
  @DisplayName("on UserRegisteredEvent the listener creates the user's default account")
  void createsDefaultAccountForRegisteredUser() {
    UserRegisteredEvent event = new UserRegisteredEvent(42L);

    // Direct handler invocation — production goes through Spring's event bus reflection.
    listener.handleUserRegistration(event);

    // The userId must pass through untransformed; what createDefaultAccount does belongs to
    // AccountServiceTest.
    verify(accountService).createDefaultAccount(42L);
  }
}
