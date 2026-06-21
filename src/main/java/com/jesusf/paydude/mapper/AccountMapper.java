package com.jesusf.paydude.mapper;

import com.jesusf.paydude.dto.account.AccountResponse;
import com.jesusf.paydude.entity.Account;
import org.mapstruct.Mapper;

/**
 * MapStruct mapper from the {@link Account} entity to its {@link AccountResponse}
 * read model. The mapping is field-name trivial, so the implementation is
 * generated at build time with no explicit {@code @Mapping} rules.
 */
@Mapper(componentModel = "spring")
public interface AccountMapper {

  /**
   * @param account the entity to convert
   * @return the corresponding response DTO
   */
  AccountResponse toResponse(Account account);
}
