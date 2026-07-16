package com.portfolio.iam.repository;

import com.portfolio.iam.domain.entity.Group;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupRepository extends JpaRepository<Group, Long> {

    Optional<Group> findByNameAndTenantId(String name, String tenantId);

    Optional<Group> findByIdAndTenantId(Long id, String tenantId);

    List<Group> findAllByTenantId(String tenantId);

    boolean existsByNameAndTenantId(String name, String tenantId);
}
