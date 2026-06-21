package com.jesusf.paydude.mapper;

import com.jesusf.paydude.dto.audit.SecurityAuditEventResponse;
import com.jesusf.paydude.entity.SecurityAuditEvent;
import org.mapstruct.Mapper;

/**
 * MapStruct mapper from the {@link SecurityAuditEvent} entity to its
 * {@link SecurityAuditEventResponse} read model.
 *
 * <p>Every field maps by name; the {@code eventType} and {@code outcome} enums map to their
 * {@code name()} strings automatically.
 */
@Mapper(componentModel = "spring")
public interface SecurityAuditEventMapper {

  /**
   * Converts an audit row to its response DTO.
   *
   * @param event the entity to convert
   * @return the corresponding response DTO
   */
  SecurityAuditEventResponse toResponse(SecurityAuditEvent event);
}
