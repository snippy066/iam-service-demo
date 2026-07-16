package com.portfolio.iam.repository;

import com.portfolio.iam.domain.entity.User;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Page<User> findByTenantId(String tenantId, Pageable pageable);

    Optional<User> findByEmailAndTenantId(String email, String tenantId);

    Optional<User> findByIdAndTenantId(Long id, String tenantId);

    boolean existsByEmailAndTenantId(String email, String tenantId);
}
