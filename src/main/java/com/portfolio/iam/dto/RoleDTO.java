package com.portfolio.iam.dto;

import com.portfolio.iam.domain.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RoleDTO(
        Long id,
        @NotBlank @Size(max = 64) String name,
        @Size(max = 255) String description) {

    public static RoleDTO from(Role role) {
        return new RoleDTO(role.getId(), role.getName(), role.getDescription());
    }
}
