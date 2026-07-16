package com.portfolio.iam.service;

import com.portfolio.iam.repository.RefreshTokenRepository;
import com.portfolio.iam.repository.RevokedAccessTokenRepository;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Periodically purges expired refresh tokens and access-token blacklist entries
 * so those tables do not grow unbounded. A revoked-access-token entry is only
 * useful until the token would have expired anyway.
 */
@Component
public class TokenCleanupScheduler {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupScheduler.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final RevokedAccessTokenRepository revokedAccessTokenRepository;

    public TokenCleanupScheduler(RefreshTokenRepository refreshTokenRepository,
                                 RevokedAccessTokenRepository revokedAccessTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.revokedAccessTokenRepository = revokedAccessTokenRepository;
    }

    /** Runs hourly (also once ~5 minutes after startup). */
    @Scheduled(fixedDelayString = "PT1H", initialDelayString = "PT5M")
    @Transactional
    public void purgeExpiredTokens() {
        Instant now = Instant.now();
        int refreshDeleted = refreshTokenRepository.deleteByExpiresAtBefore(now);
        int revokedDeleted = revokedAccessTokenRepository.deleteByExpiresAtBefore(now);
        if (refreshDeleted > 0 || revokedDeleted > 0) {
            log.info("Token cleanup purged {} refresh token(s) and {} revoked access-token entrie(s).",
                    refreshDeleted, revokedDeleted);
        }
    }
}
