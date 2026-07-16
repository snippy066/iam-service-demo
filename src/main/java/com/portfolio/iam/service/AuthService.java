package com.portfolio.iam.service;

import com.portfolio.iam.config.AppProperties;
import com.portfolio.iam.domain.entity.AuditAction;
import com.portfolio.iam.domain.entity.RefreshToken;
import com.portfolio.iam.domain.entity.RevokedAccessToken;
import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.dto.LoginRequest;
import com.portfolio.iam.dto.RegisterRequest;
import com.portfolio.iam.dto.TokenResponse;
import com.portfolio.iam.dto.UserDTO;
import com.portfolio.iam.repository.RefreshTokenRepository;
import com.portfolio.iam.repository.RevokedAccessTokenRepository;
import com.portfolio.iam.repository.RoleRepository;
import com.portfolio.iam.repository.UserRepository;
import com.portfolio.iam.security.AuthenticatedUser;
import com.portfolio.iam.security.JwtService;
import com.portfolio.iam.web.exception.AccountLockedException;
import com.portfolio.iam.web.exception.ConflictException;
import com.portfolio.iam.web.exception.TwoFactorRequiredException;
import com.portfolio.iam.web.exception.UnauthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Core authentication workflows: registration, login (with lockout and optional
 * 2FA), refresh-token rotation and logout / token revocation.
 */
@Service
public class AuthService {

    private static final String ROLE_USER = "ROLE_USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RevokedAccessTokenRepository revokedAccessTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TwoFactorService twoFactorService;
    private final AuditService auditService;
    private final AppProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       RevokedAccessTokenRepository revokedAccessTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       TwoFactorService twoFactorService,
                       AuditService auditService,
                       AppProperties properties) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.revokedAccessTokenRepository = revokedAccessTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.twoFactorService = twoFactorService;
        this.auditService = auditService;
        this.properties = properties;
    }

    /** Registers a self-service user in the given tenant with the default ROLE_USER. */
    @Transactional
    public UserDTO register(RegisterRequest request, String tenantId) {
        if (userRepository.existsByEmailAndTenantId(request.email(), tenantId)) {
            throw new ConflictException("An account with this email already exists.");
        }
        Role userRole = roleRepository.findByName(ROLE_USER)
                .orElseGet(() -> roleRepository.save(Role.builder().name(ROLE_USER)
                        .description("Standard user").build()));

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(request.fullName())
                .tenantId(tenantId)
                .enabled(true)
                .build();
        user.getRoles().add(userRole);
        User saved = userRepository.save(user);
        auditService.record(tenantId, saved.getId(), AuditAction.USER_CREATED,
                Map.of("email", saved.getEmail(), "self_service", true));
        return UserDTO.from(saved);
    }

    /** Authenticates a user and issues an access + refresh token pair. */
    @Transactional
    public TokenResponse login(LoginRequest request, String tenantId, String deviceInfo) {
        User user = userRepository.findByEmailAndTenantId(request.email(), tenantId)
                .orElseThrow(() -> {
                    auditService.record(tenantId, null, AuditAction.LOGIN_FAILURE,
                            Map.of("email", request.email(), "reason", "unknown_user"));
                    return new BadCredentialsException("Invalid email or password.");
                });

        if (user.isLocked()) {
            auditService.record(tenantId, user.getId(), AuditAction.LOGIN_FAILURE,
                    Map.of("reason", "account_locked"));
            throw new AccountLockedException("Account is locked due to too many failed login attempts.");
        }
        if (!user.isEnabled()) {
            throw new AccountLockedException("Account is disabled.");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerFailedAttempt(user);
            throw new BadCredentialsException("Invalid email or password.");
        }

        if (user.isTwoFactorEnabled()) {
            if (request.totpCode() == null || request.totpCode().isBlank()) {
                throw new TwoFactorRequiredException("A two-factor authentication code is required.");
            }
            if (!twoFactorService.verifyCode(user.getTotpSecret(), request.totpCode())) {
                registerFailedAttempt(user);
                throw new UnauthorizedException("Invalid two-factor code.");
            }
        }

        // Success: reset counters and issue tokens.
        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        auditService.record(tenantId, user.getId(), AuditAction.LOGIN_SUCCESS, Map.of());
        return issueTokens(user, deviceInfo);
    }

    /**
     * Rotates a refresh token: validates it, revokes it, and issues a brand-new
     * access + refresh token pair. A revoked/expired/unknown token is rejected.
     */
    @Transactional
    public TokenResponse refresh(String rawRefreshToken, String deviceInfo) {
        String hash = sha256(rawRefreshToken);
        RefreshToken stored = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token."));

        if (!stored.isActive()) {
            throw new UnauthorizedException("Refresh token is expired or has been revoked.");
        }

        User user = userRepository.findByIdAndTenantId(stored.getUserId(), stored.getTenantId())
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token."));
        if (user.isLocked() || !user.isEnabled()) {
            throw new AccountLockedException("Account is locked or disabled.");
        }

        // Rotation: invalidate the presented token before issuing a new one.
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        auditService.record(user.getTenantId(), user.getId(), AuditAction.TOKEN_REFRESH, Map.of());
        return issueTokens(user, deviceInfo);
    }

    /** Revokes the current access token (by jti) and, if supplied, a refresh token. */
    @Transactional
    public void logout(AuthenticatedUser principal, String rawRefreshToken) {
        if (principal.jti() != null && !revokedAccessTokenRepository.existsByJti(principal.jti())) {
            Instant expiry = Instant.now().plus(jwtService.getAccessTokenTtlSeconds(), ChronoUnit.SECONDS);
            revokedAccessTokenRepository.save(RevokedAccessToken.builder()
                    .jti(principal.jti())
                    .expiresAt(expiry)
                    .build());
        }
        if (rawRefreshToken != null && !rawRefreshToken.isBlank()) {
            refreshTokenRepository.findByTokenHash(sha256(rawRefreshToken)).ifPresent(rt -> {
                rt.setRevoked(true);
                refreshTokenRepository.save(rt);
            });
        }
        auditService.record(principal.tenantId(), principal.userId(), AuditAction.LOGOUT, Map.of());
    }

    private TokenResponse issueTokens(User user, String deviceInfo) {
        String accessToken = jwtService.createAccessToken(user);
        String rawRefreshToken = generateRefreshToken();
        Instant expiresAt = Instant.now().plus(
                properties.security().jwt().refreshTokenTtl(), ChronoUnit.SECONDS);

        refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash(sha256(rawRefreshToken))
                .userId(user.getId())
                .tenantId(user.getTenantId())
                .expiresAt(expiresAt)
                .deviceInfo(deviceInfo)
                .build());

        return TokenResponse.bearer(accessToken, rawRefreshToken, jwtService.getAccessTokenTtlSeconds());
    }

    private void registerFailedAttempt(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        int max = properties.security().lockout().maxFailedAttempts();
        Map<String, Object> details;
        if (attempts >= max) {
            user.setLocked(true);
            details = Map.of("reason", "bad_password", "attempts", attempts, "locked", true);
            userRepository.save(user);
            auditService.record(user.getTenantId(), user.getId(), AuditAction.USER_LOCKED, details);
        } else {
            details = Map.of("reason", "bad_password", "attempts", attempts);
            userRepository.save(user);
        }
        auditService.record(user.getTenantId(), user.getId(), AuditAction.LOGIN_FAILURE, details);
    }

    private String generateRefreshToken() {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }
}
