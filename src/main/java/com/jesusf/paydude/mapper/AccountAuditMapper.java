package com.jesusf.paydude.mapper;

import com.jesusf.paydude.dto.account.AccountAuditResponse;
import com.jesusf.paydude.entity.AccountAudit;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

/**
 * MapStruct mapper from the {@link AccountAudit} entity to its
 * {@link AccountAuditResponse} read model.
 */
@Mapper(componentModel = "spring")
public interface AccountAuditMapper {

  /**
   * Converts an audit row to its response DTO.
   *
   * <p>The {@code transaction} association is flattened to a bare
   * {@code transactionId}. MapStruct emits a null-safe navigation, so a deposit
   * or withdrawal row — which has no linked transaction — maps cleanly to a
   * {@code null} id.
   *
   * @param audit the entity to convert
   * @return the corresponding response DTO
   */
  @Mapping(target = "transactionId", source = "transaction.id")
  AccountAuditResponse toResponse(AccountAudit audit);
}
