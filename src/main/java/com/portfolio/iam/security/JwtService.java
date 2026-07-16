package com.portfolio.iam.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.portfolio.iam.config.AppProperties;
import com.portfolio.iam.domain.entity.User;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

/**
 * Creates and verifies short-lived HMAC-signed access tokens (java-jwt / HS256).
 *
 * <p>Claims: {@code sub}=userId, {@code email}, {@code tenantId}, {@code roles},
 * a unique {@code jti} (used for revocation) and standard {@code iat}/{@code exp}.
 */
@Service
public class JwtService {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_TENANT = "tenantId";
    private static final String CLAIM_ROLES = "roles";

    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final String issuer;
    private final long accessTokenTtlSeconds;

    public JwtService(AppProperties properties) {
        AppProperties.Security.Jwt jwt = properties.security().jwt();
        if (jwt.secret() == null || jwt.secret().isBlank()) {
            throw new IllegalStateException(
                    "app.security.jwt.secret must be configured (set the JWT_SECRET environment variable).");
        }
        this.algorithm = Algorithm.HMAC256(jwt.secret());
        this.issuer = jwt.issuer();
        this.accessTokenTtlSeconds = jwt.accessTokenTtl();
        this.verifier = JWT.require(algorithm).withIssuer(issuer).build();
    }

    /** @return the configured access-token lifetime in seconds. */
    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    /**
     * Issues a signed access token for the given user.
     *
     * @return the compact JWT string
     */
    public String createAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenTtlSeconds, ChronoUnit.SECONDS);
        List<String> roles = user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toList());

        return JWT.create()
                .withIssuer(issuer)
                .withSubject(String.valueOf(user.getId()))
                .withClaim(CLAIM_EMAIL, user.getEmail())
                .withClaim(CLAIM_TENANT, user.getTenantId())
                .withClaim(CLAIM_ROLES, roles)
                .withJWTId(UUID.randomUUID().toString())
                .withIssuedAt(now)
                .withExpiresAt(expiry)
                .sign(algorithm);
    }

    /**
     * Verifies the signature, issuer and expiry of a token and returns its parsed
     * principal.
     *
     * @throws JWTVerificationException if the token is invalid, tampered or expired
     */
    public AuthenticatedUser parse(String token) {
        DecodedJWT decoded = verifier.verify(token);
        Set<String> roles = decoded.getClaim(CLAIM_ROLES).asList(String.class)
                .stream().collect(Collectors.toSet());
        return new AuthenticatedUser(
                Long.valueOf(decoded.getSubject()),
                decoded.getClaim(CLAIM_EMAIL).asString(),
                decoded.getClaim(CLAIM_TENANT).asString(),
                decoded.getId(),
                roles);
    }

    /** @return the token's {@code exp} instant (verifying the token first). */
    public Instant getExpiry(String token) {
        return verifier.verify(token).getExpiresAt().toInstant();
    }
}
