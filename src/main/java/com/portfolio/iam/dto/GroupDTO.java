package com.portfolio.iam.dto;

import com.portfolio.iam.domain.entity.Group;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;
import java.util.stream.Collectors;

public record GroupDTO(
        Long id,
        @NotBlank @Size(max = 128) String name,
        @Size(max = 255) String description,
        String tenantId,
        Set<String> roles) {

    public static GroupDTO from(Group group) {
        return new GroupDTO(
                group.getId(),
                group.getName(),
                group.getDescription(),
                group.getTenantId(),
                group.getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet()));
    }
}
