package com.portfolio.iam.controller;

import com.portfolio.iam.dto.AssignGroupsRequest;
import com.portfolio.iam.dto.AssignRolesRequest;
import com.portfolio.iam.dto.ChangePasswordRequest;
import com.portfolio.iam.dto.CreateUserRequest;
import com.portfolio.iam.dto.PageResponse;
import com.portfolio.iam.dto.UpdateUserRequest;
import com.portfolio.iam.dto.UserDTO;
import com.portfolio.iam.security.AuthenticatedUser;
import com.portfolio.iam.security.CurrentUser;
import com.portfolio.iam.security.TenantContext;
import com.portfolio.iam.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * User administration. All endpoints require ROLE_ADMIN except the self-service
 * password change.
 */
@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Users", description = "User administration, role/group assignment, lock/unlock")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "List users (admin)")
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<UserDTO> list(@RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "20") int size) {
        return PageResponse.of(
                userService.list(TenantContext.getTenantId(),
                        PageRequest.of(page, size, Sort.by("id").ascending())),
                UserDTO::from);
    }

    @Operation(summary = "Get a user by id (admin)")
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO get(@PathVariable Long id) {
        return userService.get(id, TenantContext.getTenantId());
    }

    @Operation(summary = "Create a user (admin)")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO create(@Valid @RequestBody CreateUserRequest request) {
        return userService.create(request, TenantContext.getTenantId());
    }

    @Operation(summary = "Update a user (admin)")
    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO update(@PathVariable Long id, @Valid @RequestBody UpdateUserRequest request) {
        return userService.update(id, request, TenantContext.getTenantId());
    }

    @Operation(summary = "Delete a user (admin)")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void delete(@PathVariable Long id) {
        userService.delete(id, TenantContext.getTenantId());
    }

    @Operation(summary = "Assign roles to a user (admin)")
    @PostMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO assignRoles(@PathVariable Long id, @Valid @RequestBody AssignRolesRequest request) {
        return userService.assignRoles(id, request.roles(), TenantContext.getTenantId());
    }

    @Operation(summary = "Revoke a role from a user (admin)")
    @DeleteMapping("/{id}/roles/{roleName}")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO revokeRole(@PathVariable Long id, @PathVariable String roleName) {
        return userService.revokeRole(id, roleName, TenantContext.getTenantId());
    }

    @Operation(summary = "Assign groups to a user (admin)")
    @PostMapping("/{id}/groups")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO assignGroups(@PathVariable Long id, @Valid @RequestBody AssignGroupsRequest request) {
        return userService.assignGroups(id, request.groupIds(), TenantContext.getTenantId());
    }

    @Operation(summary = "Lock a user (admin)")
    @PutMapping("/{id}/lock")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO lock(@PathVariable Long id) {
        return userService.setLocked(id, true, TenantContext.getTenantId());
    }

    @Operation(summary = "Unlock a user (admin)")
    @PutMapping("/{id}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO unlock(@PathVariable Long id) {
        return userService.setLocked(id, false, TenantContext.getTenantId());
    }

    @Operation(summary = "Change your own password")
    @PostMapping("/me/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        AuthenticatedUser principal = CurrentUser.require();
        userService.changePassword(principal.userId(), principal.tenantId(), request);
    }
}
