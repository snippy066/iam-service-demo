package com.portfolio.iam.controller;

import com.portfolio.iam.dto.AssignRolesRequest;
import com.portfolio.iam.dto.GroupDTO;
import com.portfolio.iam.security.TenantContext;
import com.portfolio.iam.service.GroupService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/groups")
@Tag(name = "Groups", description = "Tenant-scoped group administration (groups grant roles)")
@SecurityRequirement(name = "bearerAuth")
@PreAuthorize("hasRole('ADMIN')")
public class GroupController {

    private final GroupService groupService;

    public GroupController(GroupService groupService) {
        this.groupService = groupService;
    }

    @Operation(summary = "List groups in the current tenant")
    @GetMapping
    public List<GroupDTO> list() {
        return groupService.list(TenantContext.getTenantId());
    }

    @Operation(summary = "Get a group by id")
    @GetMapping("/{id}")
    public GroupDTO get(@PathVariable Long id) {
        return groupService.get(id, TenantContext.getTenantId());
    }

    @Operation(summary = "Create a group")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public GroupDTO create(@Valid @RequestBody GroupDTO request) {
        return groupService.create(request, TenantContext.getTenantId());
    }

    @Operation(summary = "Replace the roles granted by a group")
    @PutMapping("/{id}/roles")
    public GroupDTO updateRoles(@PathVariable Long id, @Valid @RequestBody AssignRolesRequest request) {
        return groupService.updateRoles(id, request.roles(), TenantContext.getTenantId());
    }

    @Operation(summary = "Delete a group")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        groupService.delete(id, TenantContext.getTenantId());
    }
}
