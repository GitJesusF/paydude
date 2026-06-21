package com.jesusf.paydude.event;

/**
 * Published by {@code AuthServiceImpl.register} once a new user row is persisted.
 *
 * <p>{@code AccountEventListener} consumes it at {@code BEFORE_COMMIT} to open a
 * default account in the same transaction — so the user and their account are
 * created, or rolled back, together.
 *
 * @param userId the id of the newly registered user
 */
public record UserRegisteredEvent(Long userId) {
}
