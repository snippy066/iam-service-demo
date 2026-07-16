package com.portfolio.iam.security;

import java.util.Set;

/**
 * Lightweight principal stored in the {@code SecurityContext} after a bearer token
 * has been validated. Carries the identity and tenant needed by controllers and
 * services without a database round-trip on every request.
 *
 * @param userId   authenticated user's id
 * @param email    authenticated user's email
 * @param tenantId tenant the token was issued for
 * @param jti      token identifier (for revocation / logout)
 * @param roles    granted role names (e.g. {@code ROLE_ADMIN})
 */
public record AuthenticatedUser(
        Long userId,
        String email,
        String tenantId,
        String jti,
        Set<String> roles) {
}
