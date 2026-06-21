package com.jesusf.paydude.mapper;

import com.jesusf.paydude.dto.user.UserResponse;
import com.jesusf.paydude.dto.user.UserResponseV2;
import com.jesusf.paydude.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

/**
 * MapStruct mapper from the {@link User} entity to its public read models.
 *
 * <p>The {@code role} and {@code status} enums are exposed as their {@code name()}
 * strings so the JSON contract stays decoupled from the Java enum types.
 */
@Mapper(componentModel = "spring")
public interface UserMapper {

  /**
   * Converts a user to the v1 profile response.
   *
   * @param user the entity to convert
   * @return the v1 response DTO
   */
  @Mapping(target = "role", expression = "java(user.getRole().name())")
  @Mapping(target = "status", expression = "java(user.getStatus().name())")
  UserResponse toResponse(User user);

  /**
   * Converts a user to the v2 profile response, which additionally carries
   * {@code createdAt}.
   *
   * @param user the entity to convert
   * @return the v2 response DTO
   */
  @Mapping(target = "role", expression = "java(user.getRole().name())")
  @Mapping(target = "status", expression = "java(user.getStatus().name())")
  UserResponseV2 toResponseV2(User user);
}
