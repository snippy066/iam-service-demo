package com.portfolio.iam.dto;

import com.portfolio.iam.domain.entity.User;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

/** Read model for a user. Never exposes the password hash or TOTP secret. */
public record UserDTO(
        Long id,
        String email,
        String fullName,
        String tenantId,
        boolean enabled,
        boolean locked,
        boolean twoFactorEnabled,
        Set<String> roles,
        Set<String> groups,
        Instant createdAt,
        Instant lastLoginAt) {

    public static UserDTO from(User user) {
        return new UserDTO(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getTenantId(),
                user.isEnabled(),
                user.isLocked(),
                user.isTwoFactorEnabled(),
                user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet()),
                user.getGroups().stream().map(g -> g.getName()).collect(Collectors.toSet()),
                user.getCreatedAt(),
                user.getLastLoginAt());
    }
}
