package com.portfolio.iam.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.portfolio.iam.config.AppProperties;
import com.portfolio.iam.domain.entity.RefreshToken;
import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.dto.LoginRequest;
import com.portfolio.iam.dto.RegisterRequest;
import com.portfolio.iam.dto.TokenResponse;
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
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String TENANT = "primary";

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private RevokedAccessTokenRepository revokedAccessTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private TwoFactorService twoFactorService;
    @Mock private AuditService auditService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        AppProperties properties = new AppProperties(
                new AppProperties.Security(
                        new AppProperties.Security.Jwt("secret", "iam-service", 900, 3600),
                        new AppProperties.Security.Lockout(3)),
                null);
        authService = new AuthService(userRepository, roleRepository, refreshTokenRepository,
                revokedAccessTokenRepository, passwordEncoder, jwtService, twoFactorService,
                auditService, properties);
    }

    private User existingUser() {
        User user = User.builder()
                .id(1L).email("bob@example.com").passwordHash("hashed")
                .fullName("Bob").tenantId(TENANT).enabled(true).build();
        user.getRoles().add(Role.builder().id(1L).name("ROLE_USER").build());
        return user;
    }

    @Test
    void register_createsUserWithDefaultRole() {
        when(userRepository.existsByEmailAndTenantId("new@example.com", TENANT)).thenReturn(false);
        when(roleRepository.findByName("ROLE_USER"))
                .thenReturn(Optional.of(Role.builder().id(1L).name("ROLE_USER").build()));
        when(passwordEncoder.encode("password123")).thenReturn("ENC");
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        var dto = authService.register(new RegisterRequest("new@example.com", "password123", "New"), TENANT);

        assertThat(dto.email()).isEqualTo("new@example.com");
        assertThat(dto.roles()).contains("ROLE_USER");
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("ENC");
    }

    @Test
    void register_rejectsDuplicateEmail() {
        when(userRepository.existsByEmailAndTenantId("dupe@example.com", TENANT)).thenReturn(true);

        assertThatThrownBy(() -> authService.register(
                new RegisterRequest("dupe@example.com", "password123", "Dupe"), TENANT))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void login_succeeds_issuesTokenPair() {
        User user = existingUser();
        when(userRepository.findByEmailAndTenantId("bob@example.com", TENANT)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hashed")).thenReturn(true);
        when(jwtService.createAccessToken(user)).thenReturn("access-token");
        when(jwtService.getAccessTokenTtlSeconds()).thenReturn(900L);
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TokenResponse response = authService.login(
                new LoginRequest("bob@example.com", "secret", null), TENANT, "junit");

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isNotBlank();
        assertThat(response.expiresIn()).isEqualTo(900L);
        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLastLoginAt()).isNotNull();
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void login_badPassword_incrementsAndEventuallyLocks() {
        User user = existingUser();
        user.setFailedLoginAttempts(2); // one below the configured max of 3
        when(userRepository.findByEmailAndTenantId("bob@example.com", TENANT)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("bob@example.com", "wrong", null), TENANT, "junit"))
                .isInstanceOf(BadCredentialsException.class);

        assertThat(user.getFailedLoginAttempts()).isEqualTo(3);
        assertThat(user.isLocked()).isTrue();
    }

    @Test
    void login_lockedAccount_isRejected() {
        User user = existingUser();
        user.setLocked(true);
        when(userRepository.findByEmailAndTenantId("bob@example.com", TENANT)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("bob@example.com", "secret", null), TENANT, "junit"))
                .isInstanceOf(AccountLockedException.class);
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    void login_twoFactorEnabled_requiresCode() {
        User user = existingUser();
        user.setTwoFactorEnabled(true);
        user.setTotpSecret("SECRET");
        when(userRepository.findByEmailAndTenantId("bob@example.com", TENANT)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hashed")).thenReturn(true);

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("bob@example.com", "secret", null), TENANT, "junit"))
                .isInstanceOf(TwoFactorRequiredException.class);
    }

    @Test
    void login_twoFactorEnabled_succeedsWithValidCode() {
        User user = existingUser();
        user.setTwoFactorEnabled(true);
        user.setTotpSecret("SECRET");
        when(userRepository.findByEmailAndTenantId("bob@example.com", TENANT)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hashed")).thenReturn(true);
        when(twoFactorService.verifyCode("SECRET", "123456")).thenReturn(true);
        when(jwtService.createAccessToken(user)).thenReturn("access-token");
        when(jwtService.getAccessTokenTtlSeconds()).thenReturn(900L);
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TokenResponse response = authService.login(
                new LoginRequest("bob@example.com", "secret", "123456"), TENANT, "junit");

        assertThat(response.accessToken()).isEqualTo("access-token");
    }

    @Test
    void refresh_rotatesToken_revokingOld() {
        User user = existingUser();
        RefreshToken stored = RefreshToken.builder()
                .id(10L).userId(1L).tenantId(TENANT)
                .tokenHash("hash").expiresAt(Instant.now().plusSeconds(3600)).revoked(false)
                .build();
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(jwtService.createAccessToken(user)).thenReturn("new-access");
        when(jwtService.getAccessTokenTtlSeconds()).thenReturn(900L);
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TokenResponse response = authService.refresh("raw-refresh-token", "junit");

        assertThat(response.accessToken()).isEqualTo("new-access");
        assertThat(response.refreshToken()).isNotBlank();
        assertThat(stored.isRevoked()).isTrue(); // old token rotated out
    }

    @Test
    void refresh_rejectsRevokedToken() {
        RefreshToken stored = RefreshToken.builder()
                .id(10L).userId(1L).tenantId(TENANT)
                .tokenHash("hash").expiresAt(Instant.now().plusSeconds(3600)).revoked(true)
                .build();
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> authService.refresh("raw", "junit"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void refresh_rejectsUnknownToken() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("raw", "junit"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void logout_revokesAccessAndRefreshToken() {
        AuthenticatedUser principal = new AuthenticatedUser(1L, "bob@example.com", TENANT, "jti-1",
                Set.of("ROLE_USER"));
        when(revokedAccessTokenRepository.existsByJti("jti-1")).thenReturn(false);
        when(jwtService.getAccessTokenTtlSeconds()).thenReturn(900L);
        RefreshToken stored = RefreshToken.builder().id(5L).revoked(false)
                .expiresAt(Instant.now().plusSeconds(3600)).build();
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.logout(principal, "raw-refresh");

        verify(revokedAccessTokenRepository).save(any());
        assertThat(stored.isRevoked()).isTrue();
        verify(auditService).record(eq(TENANT), eq(1L), any(), any());
    }
}
