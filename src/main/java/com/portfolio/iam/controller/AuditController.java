package com.portfolio.iam.controller;

import com.portfolio.iam.dto.AuditEventDTO;
import com.portfolio.iam.dto.PageResponse;
import com.portfolio.iam.security.TenantContext;
import com.portfolio.iam.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only access to the security audit log for the current tenant (admin only).
 */
@RestController
@RequestMapping("/api/v1/audit")
@Tag(name = "Audit", description = "Security audit event log")
@SecurityRequirement(name = "bearerAuth")
@PreAuthorize("hasRole('ADMIN')")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @Operation(summary = "Query audit events (admin)", description = "Paginated, newest first. "
            + "Optionally filter by userId.")
    @GetMapping
    public PageResponse<AuditEventDTO> query(@RequestParam(required = false) Long userId,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(defaultValue = "20") int size) {
        return PageResponse.of(
                auditService.query(TenantContext.getTenantId(), userId, PageRequest.of(page, size)),
                AuditEventDTO::from);
    }
}
