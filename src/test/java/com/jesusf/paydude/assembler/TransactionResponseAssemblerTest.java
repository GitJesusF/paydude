package com.jesusf.paydude.assembler;

import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.Transaction;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.mapper.TransactionMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link TransactionResponseAssembler}.
 *
 * <p>The assembler decides two things that depend on the caller's perspective: whether a
 * transaction was SENT or RECEIVED by the current user, and who the counterparty is. Pinning
 * both cases — plus the external-bank fallback when one side of the transaction is null —
 * is essential because this logic lives outside the mapper on purpose and is therefore easy
 * to break with an innocent refactor.
 *
 * <p>Entities are built with their Lombok builders, not mocked: they are plain POJOs and
 * stubbing every getter would add noise without isolation. The assembler delegates DTO
 * construction to the mapper, so verifying the mapper invocation covers its whole contract.
 */
@ExtendWith(MockitoExtension.class)
class TransactionResponseAssemblerTest {

  @Mock
  private TransactionMapper transactionMapper;

  @InjectMocks
  private TransactionResponseAssembler assembler;

  @Test
  @DisplayName("when current user is the sender, type=SENT and counterparty is the target user")
  void sentTransaction() {
    User sender = User.builder().id(1L).firstName("Alice").lastName("Smith").build();
    User receiver = User.builder().id(2L).firstName("Bob").lastName("Jones").build();
    Account source = Account.builder().user(sender).accountNumber("4520000000000001").build();
    Account target = Account.builder().user(receiver).accountNumber("4520000000000002").build();
    Transaction tx = Transaction.builder().sourceAccount(source).targetAccount(target).build();

    assembler.toResponse(tx, 1L);

    // The counterparty account arrives masked to last-4: the caller is not its owner, so the
    // assembler never exposes the full number (data minimization).
    verify(transactionMapper).toDto(tx, "SENT", "Bob Jones", "****0002");
  }

  @Test
  @DisplayName("when current user is the receiver, type=RECEIVED and counterparty is the source user")
  void receivedTransaction() {
    User sender = User.builder().id(1L).firstName("Alice").lastName("Smith").build();
    User receiver = User.builder().id(2L).firstName("Bob").lastName("Jones").build();
    Account source = Account.builder().user(sender).accountNumber("4520000000000001").build();
    Account target = Account.builder().user(receiver).accountNumber("4520000000000002").build();
    Transaction tx = Transaction.builder().sourceAccount(source).targetAccount(target).build();

    assembler.toResponse(tx, 2L);

    verify(transactionMapper).toDto(tx, "RECEIVED", "Alice Smith", "****0001");
  }

  // The next two tests exercise the "external" path — one side of the transaction is null. The
  // schema allows nullable source/target (V0_001) for movements against entities outside the
  // bank; the current flow only creates internal transactions, but the assembler must support
  // the future case without an NPE.

  @Test
  @DisplayName("when source is null (external deposit), counterparty defaults to External Bank/N/A")
  void externalDepositFallsBackToPlaceholders() {
    User receiver = User.builder().id(2L).firstName("Bob").lastName("Jones").build();
    Account target = Account.builder().user(receiver).accountNumber("4520000000000002").build();
    Transaction tx = Transaction.builder().sourceAccount(null).targetAccount(target).build();

    assembler.toResponse(tx, 2L);

    // "External Bank" / "N/A" are pinned as contract: changing them must be a conscious decision.
    verify(transactionMapper).toDto(tx, "RECEIVED", "External Bank", "N/A");
  }

  @Test
  @DisplayName("when target is null (external withdraw by current user), counterparty defaults to External Bank/N/A")
  void externalWithdrawFallsBackToPlaceholders() {
    User sender = User.builder().id(1L).firstName("Alice").lastName("Smith").build();
    Account source = Account.builder().user(sender).accountNumber("4520000000000001").build();
    Transaction tx = Transaction.builder().sourceAccount(source).targetAccount(null).build();

    assembler.toResponse(tx, 1L);

    verify(transactionMapper).toDto(tx, "SENT", "External Bank", "N/A");
  }

  @Test
  @DisplayName("null transaction throws NullPointerException")
  void nullTransactionThrows() {
    // Deliberate fail-fast (Objects.requireNonNull at the component boundary): a null here is
    // always a caller bug, better surfaced with a localized stack trace.
    assertThrows(NullPointerException.class, () -> assembler.toResponse(null, 1L));
  }
}
