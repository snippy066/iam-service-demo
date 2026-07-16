package com.portfolio.iam.repository;

import com.portfolio.iam.domain.entity.RevokedAccessToken;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

@Repository
public interface RevokedAccessTokenRepository extends JpaRepository<RevokedAccessToken, Long> {

    boolean existsByJti(String jti);

    @Modifying
    int deleteByExpiresAtBefore(Instant cutoff);
}
