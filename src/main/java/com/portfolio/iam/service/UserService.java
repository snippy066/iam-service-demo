package com.portfolio.iam.service;

import com.portfolio.iam.domain.entity.AuditAction;
import com.portfolio.iam.domain.entity.Group;
import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.dto.ChangePasswordRequest;
import com.portfolio.iam.dto.CreateUserRequest;
import com.portfolio.iam.dto.UpdateUserRequest;
import com.portfolio.iam.dto.UserDTO;
import com.portfolio.iam.repository.GroupRepository;
import com.portfolio.iam.repository.RefreshTokenRepository;
import com.portfolio.iam.repository.RoleRepository;
import com.portfolio.iam.repository.UserRepository;
import com.portfolio.iam.web.exception.ConflictException;
import com.portfolio.iam.web.exception.NotFoundException;
import com.portfolio.iam.web.exception.UnauthorizedException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * User administration: CRUD, role/group assignment, lock/unlock and password
 * change. All lookups are scoped to the caller's tenant.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final GroupRepository groupRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       GroupRepository groupRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       AuditService auditService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.groupRepository = groupRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public Page<User> list(String tenantId, Pageable pageable) {
        // Tenant scoping enforced at the query level so one tenant can never page
        // through another tenant's users.
        return userRepository.findByTenantId(tenantId, pageable);
    }

    @Transactional(readOnly = true)
    public UserDTO get(Long id, String tenantId) {
        return UserDTO.from(requireUser(id, tenantId));
    }

    @Transactional
    public UserDTO create(CreateUserRequest request, String tenantId) {
        if (userRepository.existsByEmailAndTenantId(request.email(), tenantId)) {
            throw new ConflictException("An account with this email already exists.");
        }
        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(request.fullName())
                .tenantId(tenantId)
                .enabled(true)
                .build();
        if (request.roles() != null) {
            user.getRoles().addAll(resolveRoles(request.roles()));
        }
        User saved = userRepository.save(user);
        auditService.record(tenantId, saved.getId(), AuditAction.USER_CREATED,
                Map.of("email", saved.getEmail(), "self_service", false));
        return UserDTO.from(saved);
    }

    @Transactional
    public UserDTO update(Long id, UpdateUserRequest request, String tenantId) {
        User user = requireUser(id, tenantId);
        if (request.fullName() != null) {
            user.setFullName(request.fullName());
        }
        if (request.enabled() != null) {
            user.setEnabled(request.enabled());
        }
        User saved = userRepository.save(user);
        auditService.record(tenantId, saved.getId(), AuditAction.USER_UPDATED, Map.of());
        return UserDTO.from(saved);
    }

    @Transactional
    public void delete(Long id, String tenantId) {
        User user = requireUser(id, tenantId);
        refreshTokenRepository.revokeAllForUser(user.getId());
        userRepository.delete(user);
        auditService.record(tenantId, id, AuditAction.USER_DELETED, Map.of());
    }

    @Transactional
    public UserDTO assignRoles(Long id, Set<String> roleNames, String tenantId) {
        User user = requireUser(id, tenantId);
        user.getRoles().addAll(resolveRoles(roleNames));
        User saved = userRepository.save(user);
        auditService.record(tenantId, id, AuditAction.ROLE_ASSIGNED, Map.of("roles", roleNames));
        return UserDTO.from(saved);
    }

    @Transactional
    public UserDTO revokeRole(Long id, String roleName, String tenantId) {
        User user = requireUser(id, tenantId);
        user.getRoles().removeIf(r -> r.getName().equals(roleName));
        User saved = userRepository.save(user);
        auditService.record(tenantId, id, AuditAction.ROLE_REVOKED, Map.of("role", roleName));
        return UserDTO.from(saved);
    }

    @Transactional
    public UserDTO assignGroups(Long id, Set<Long> groupIds, String tenantId) {
        User user = requireUser(id, tenantId);
        Set<Group> groups = new HashSet<>();
        for (Long groupId : groupIds) {
            groups.add(groupRepository.findByIdAndTenantId(groupId, tenantId)
                    .orElseThrow(() -> new NotFoundException("Group " + groupId + " not found.")));
        }
        user.getGroups().addAll(groups);
        User saved = userRepository.save(user);
        auditService.record(tenantId, id, AuditAction.GROUP_ASSIGNED, Map.of("groupIds", groupIds));
        return UserDTO.from(saved);
    }

    @Transactional
    public UserDTO setLocked(Long id, boolean locked, String tenantId) {
        User user = requireUser(id, tenantId);
        user.setLocked(locked);
        if (!locked) {
            user.setFailedLoginAttempts(0);
        } else {
            refreshTokenRepository.revokeAllForUser(user.getId());
        }
        User saved = userRepository.save(user);
        auditService.record(tenantId, id, locked ? AuditAction.USER_LOCKED : AuditAction.USER_UNLOCKED, Map.of());
        return UserDTO.from(saved);
    }

    @Transactional
    public void changePassword(Long userId, String tenantId, ChangePasswordRequest request) {
        User user = requireUser(userId, tenantId);
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Current password is incorrect.");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        // Invalidate existing refresh tokens after a credential change.
        refreshTokenRepository.revokeAllForUser(user.getId());
        auditService.record(tenantId, userId, AuditAction.PASSWORD_CHANGE, Map.of());
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        Set<Role> roles = new HashSet<>();
        for (String name : roleNames) {
            roles.add(roleRepository.findByName(name)
                    .orElseThrow(() -> new NotFoundException("Role not found: " + name)));
        }
        return roles;
    }

    private User requireUser(Long id, String tenantId) {
        return userRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new NotFoundException("User not found."));
    }
}
