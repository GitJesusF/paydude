package com.jesusf.paydude.assembler;

import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.Transaction;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.TransactionType;
import com.jesusf.paydude.mapper.TransactionMapper;
import com.jesusf.paydude.util.AccountNumberMasker;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Builds a {@link TransactionResponse} from a {@link Transaction} <em>relative to the requesting
 * user</em>.
 *
 * <p>A {@link com.jesusf.paydude.mapper.TransactionMapper MapStruct mapper} alone is not enough
 * here: the same stored transfer is {@code SENT} for the sender and {@code RECEIVED} for the
 * recipient, and the "counterparty" is whichever side the caller is not. That perspective cannot
 * be derived from the entity in isolation. This assembler resolves the direction and the
 * counterparty, then delegates the flat field copy to the mapper — the standard mapper-plus-
 * assembler split for context-dependent DTO construction.
 *
 * <p>The counterparty's account number is <b>masked to its last four digits</b>
 * ({@link AccountNumberMasker}) before it leaves this layer. Data minimisation: the caller is not
 * the counterparty, so they have no authorization to see the other party's full account number —
 * a recipient learning the sender's full number is more disclosure than the history view needs.
 * The full number lives only in the audit tables and in the account's owner's own response.
 */
@Component
@RequiredArgsConstructor
public class TransactionResponseAssembler {

  private final TransactionMapper transactionMapper;

  /**
   * Renders a transaction from {@code currentUserId}'s point of view.
   *
   * <p>The counterparty account number is masked to its last four digits. If the counterparty
   * account or its owner is absent — the case the schema reserves for future external deposits and
   * withdrawals — the counterparty fields fall back to {@code "External Bank"} / {@code "N/A"}
   * rather than dereferencing a null.
   *
   * @param tx            the transaction entity to render; must not be null
   * @param currentUserId the id of the user the response is being built for
   * @return the response DTO with direction and the masked counterparty resolved for that user
   */
  public TransactionResponse toResponse(Transaction tx, Long currentUserId) {
    Objects.requireNonNull(tx, "Transaction entity must not be null for mapping");

    // 1. Determine the direction of the transaction.
    boolean isSentByMe = tx.getSourceAccount() != null &&
        tx.getSourceAccount().getUser().getId().equals(currentUserId);

    TransactionType type = isSentByMe ? TransactionType.SENT : TransactionType.RECEIVED;

    // 2. Identify the counterparty (the account on the other side of the transaction).
    Account counterpartyAccount = isSentByMe ? tx.getTargetAccount() : tx.getSourceAccount();

    String counterpartyName = "External Bank";
    String counterpartyAccountNumber = "N/A";

    if (counterpartyAccount != null && counterpartyAccount.getUser() != null) {
      User user = counterpartyAccount.getUser();
      counterpartyName = user.getFirstName() + " " + user.getLastName();
      // Mask to last-4: the caller is the other side of this transfer, not the counterparty, so
      // exposing the counterparty's full account number here is more disclosure than necessary.
      counterpartyAccountNumber = AccountNumberMasker.mask(counterpartyAccount.getAccountNumber());
    }

    // 3. Delegate the flat field mapping to the MapStruct mapper.
    return transactionMapper.toDto(
        tx,
        type.name(),
        counterpartyName,
        counterpartyAccountNumber
    );
  }
}
