package com.portfolio.iam.repository;

import com.portfolio.iam.domain.entity.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    Page<AuditEvent> findAllByTenantIdOrderByCreatedAtDesc(String tenantId, Pageable pageable);

    Page<AuditEvent> findAllByTenantIdAndUserIdOrderByCreatedAtDesc(String tenantId, Long userId, Pageable pageable);
}
