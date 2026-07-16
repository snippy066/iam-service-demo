package com.portfolio.iam.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.dto.ChangePasswordRequest;
import com.portfolio.iam.dto.CreateUserRequest;
import com.portfolio.iam.dto.UserDTO;
import com.portfolio.iam.repository.GroupRepository;
import com.portfolio.iam.repository.RefreshTokenRepository;
import com.portfolio.iam.repository.RoleRepository;
import com.portfolio.iam.repository.UserRepository;
import com.portfolio.iam.web.exception.ConflictException;
import com.portfolio.iam.web.exception.NotFoundException;
import com.portfolio.iam.web.exception.UnauthorizedException;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final String TENANT = "primary";

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private GroupRepository groupRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuditService auditService;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, roleRepository, groupRepository,
                refreshTokenRepository, passwordEncoder, auditService);
    }

    private User existingUser() {
        return User.builder()
                .id(1L).email("bob@example.com").passwordHash("hashed")
                .fullName("Bob").tenantId(TENANT).enabled(true).build();
    }

    @Test
    void create_encodesPasswordAndAssignsRoles() {
        when(userRepository.existsByEmailAndTenantId("new@example.com", TENANT)).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("ENC");
        when(roleRepository.findByName("ROLE_ADMIN"))
                .thenReturn(Optional.of(Role.builder().id(2L).name("ROLE_ADMIN").build()));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDTO dto = userService.create(
                new CreateUserRequest("new@example.com", "password123", "New", Set.of("ROLE_ADMIN")), TENANT);

        assertThat(dto.email()).isEqualTo("new@example.com");
        assertThat(dto.roles()).contains("ROLE_ADMIN");
    }

    @Test
    void create_rejectsDuplicate() {
        when(userRepository.existsByEmailAndTenantId("dupe@example.com", TENANT)).thenReturn(true);
        assertThatThrownBy(() -> userService.create(
                new CreateUserRequest("dupe@example.com", "password123", "Dupe", null), TENANT))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void changePassword_succeeds_andRevokesRefreshTokens() {
        User user = existingUser();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("old", "hashed")).thenReturn(true);
        when(passwordEncoder.encode("newpassword")).thenReturn("NEWENC");

        userService.changePassword(1L, TENANT, new ChangePasswordRequest("old", "newpassword"));

        assertThat(user.getPasswordHash()).isEqualTo("NEWENC");
        verify(refreshTokenRepository).revokeAllForUser(1L);
    }

    @Test
    void changePassword_rejectsWrongCurrentPassword() {
        User user = existingUser();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThatThrownBy(() -> userService.changePassword(1L, TENANT,
                new ChangePasswordRequest("wrong", "newpassword")))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void setLocked_locksAndRevokesTokens() {
        User user = existingUser();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDTO dto = userService.setLocked(1L, true, TENANT);

        assertThat(dto.locked()).isTrue();
        verify(refreshTokenRepository).revokeAllForUser(1L);
    }

    @Test
    void setLocked_unlockResetsFailedAttempts() {
        User user = existingUser();
        user.setLocked(true);
        user.setFailedLoginAttempts(5);
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDTO dto = userService.setLocked(1L, false, TENANT);

        assertThat(dto.locked()).isFalse();
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    void get_missingUser_throwsNotFound() {
        when(userRepository.findByIdAndTenantId(99L, TENANT)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> userService.get(99L, TENANT)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void assignRoles_addsResolvedRoles() {
        User user = existingUser();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(roleRepository.findByName("ROLE_ADMIN"))
                .thenReturn(Optional.of(Role.builder().id(2L).name("ROLE_ADMIN").build()));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDTO dto = userService.assignRoles(1L, Set.of("ROLE_ADMIN"), TENANT);

        assertThat(dto.roles()).contains("ROLE_ADMIN");
    }
}
