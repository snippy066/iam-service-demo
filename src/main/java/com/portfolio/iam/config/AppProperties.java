package com.portfolio.iam.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Strongly-typed binding for the {@code app.*} configuration tree.
 *
 * @param security  security related settings (JWT, lockout policy)
 * @param seed      demo data seeding settings (dev/seed profile only)
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(Security security, Seed seed) {

    public record Security(Jwt jwt, Lockout lockout) {

        /**
         * @param secret            HMAC secret for signing access tokens. MUST be
         *                          overridden in production via {@code JWT_SECRET}.
         * @param issuer            token issuer claim
         * @param accessTokenTtl    access token time-to-live, in seconds
         * @param refreshTokenTtl   refresh token time-to-live, in seconds
         */
        public record Jwt(String secret, String issuer, long accessTokenTtl, long refreshTokenTtl) {
        }

        /**
         * @param maxFailedAttempts number of consecutive failed logins before the
         *                          account is locked
         */
        public record Lockout(int maxFailedAttempts) {
        }
    }

    /**
     * @param enabled        whether to seed demo data on startup
     * @param tenantId       demo tenant id
     * @param adminEmail     demo admin email (DEMO ONLY)
     * @param adminPassword  demo admin password (DEMO ONLY — never a real secret)
     */
    public record Seed(boolean enabled, String tenantId, String adminEmail, String adminPassword) {
    }
}
