package com.jesusf.paydude.listener;

import com.jesusf.paydude.event.UserRegisteredEvent;
import com.jesusf.paydude.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Opens a default account for every newly registered user.
 *
 * <p>Reacting to a {@link UserRegisteredEvent} — rather than calling the account service inline
 * from {@code AuthServiceImpl} — keeps registration and account creation decoupled while still
 * atomic: the handler runs at {@code BEFORE_COMMIT}, inside the registration transaction.
 */
@Component
@RequiredArgsConstructor
public class AccountEventListener {

  private final AccountService accountService;

  /**
   * Creates the user's default account.
   *
   * <p>Runs at {@code BEFORE_COMMIT}, so it executes within the still-open registration
   * transaction: if account creation fails, the user insert rolls back too — the user and their
   * account are created, or fail, together.
   *
   * @param event the registration event carrying the new user's id
   */
  @TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
  public void handleUserRegistration(UserRegisteredEvent event) {
    accountService.createDefaultAccount(event.userId());
  }
}
