package com.portfolio.iam.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.portfolio.iam.domain.entity.AuditAction;
import com.portfolio.iam.domain.entity.AuditEvent;
import java.time.Instant;

public record AuditEventDTO(
        Long id,
        String tenantId,
        Long userId,
        AuditAction action,
        String ipAddress,
        String userAgent,
        JsonNode details,
        Instant createdAt) {

    public static AuditEventDTO from(AuditEvent event) {
        return new AuditEventDTO(
                event.getId(),
                event.getTenantId(),
                event.getUserId(),
                event.getAction(),
                event.getIpAddress(),
                event.getUserAgent(),
                event.getDetails(),
                event.getCreatedAt());
    }
}
