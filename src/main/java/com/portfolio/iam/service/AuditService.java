package com.portfolio.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.portfolio.iam.domain.entity.AuditAction;
import com.portfolio.iam.domain.entity.AuditEvent;
import com.portfolio.iam.repository.AuditEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Records and queries security audit events. Client IP and user-agent are
 * captured from the current request when available.
 */
@Service
public class AuditService {

    private final AuditEventRepository auditEventRepository;
    private final ObjectMapper objectMapper;

    public AuditService(AuditEventRepository auditEventRepository, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void record(String tenantId, Long userId, AuditAction action, Map<String, Object> details) {
        ObjectNode node = objectMapper.valueToTree(details == null ? Map.of() : details);
        AuditEvent event = AuditEvent.builder()
                .tenantId(tenantId)
                .userId(userId)
                .action(action)
                .details(node)
                .ipAddress(clientIp())
                .userAgent(userAgent())
                .build();
        auditEventRepository.save(event);
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> query(String tenantId, Long userId, Pageable pageable) {
        if (userId != null) {
            return auditEventRepository.findAllByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId, userId, pageable);
        }
        return auditEventRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId, pageable);
    }

    private String clientIp() {
        HttpServletRequest request = currentRequest();
        if (request == null) {
            return null;
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String userAgent() {
        HttpServletRequest request = currentRequest();
        return request != null ? request.getHeader("User-Agent") : null;
    }

    private HttpServletRequest currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            return attrs.getRequest();
        }
        return null;
    }
}
