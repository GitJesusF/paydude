package com.jesusf.paydude.mapper;

import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.entity.Transaction;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

/**
 * MapStruct mapper from the {@link Transaction} entity to its
 * {@link TransactionResponse} read model.
 *
 * <p>Three response fields — {@code type}, {@code counterpartyName} and
 * {@code counterpartyAccount} — depend on <em>who is asking</em>: the same stored
 * transfer is {@code SENT} for one party and {@code RECEIVED} for the other. They
 * cannot be derived from the entity alone, so they are passed in as parameters.
 * The {@code TransactionResponseAssembler} computes them from the requesting
 * user's perspective and delegates the flat field copy to this mapper.
 */
@Mapper(componentModel = "spring")
public interface TransactionMapper {

  /**
   * Converts a transaction to its response DTO, given the caller-relative fields.
   *
   * @param transaction         the entity to convert
   * @param type                {@code SENT} or {@code RECEIVED}, from the caller's perspective
   * @param counterpartyName    display name of the other party
   * @param counterpartyAccount account number of the other party
   * @return the corresponding response DTO
   */
  @Mapping(target = "id", source = "transaction.id")
  @Mapping(target = "amount", source = "transaction.amount")
  @Mapping(target = "currency", expression = "java(transaction.getCurrency().name())")
  @Mapping(target = "description", source = "transaction.description")
  @Mapping(target = "status", expression = "java(transaction.getStatus().name())")
  @Mapping(target = "date", source = "transaction.createdAt")
  @Mapping(target = "type", source = "type")
  @Mapping(target = "counterpartyName", source = "counterpartyName")
  @Mapping(target = "counterpartyAccount", source = "counterpartyAccount")
  TransactionResponse toDto(Transaction transaction, String type, String counterpartyName, String counterpartyAccount);
}
