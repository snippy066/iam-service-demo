package com.portfolio.iam.service;

import com.portfolio.iam.domain.entity.Group;
import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.dto.GroupDTO;
import com.portfolio.iam.repository.GroupRepository;
import com.portfolio.iam.repository.RoleRepository;
import com.portfolio.iam.web.exception.ConflictException;
import com.portfolio.iam.web.exception.NotFoundException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Administration of tenant-scoped groups that grant roles to their members. */
@Service
public class GroupService {

    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;

    public GroupService(GroupRepository groupRepository, RoleRepository roleRepository) {
        this.groupRepository = groupRepository;
        this.roleRepository = roleRepository;
    }

    @Transactional(readOnly = true)
    public List<GroupDTO> list(String tenantId) {
        return groupRepository.findAllByTenantId(tenantId).stream().map(GroupDTO::from).toList();
    }

    @Transactional(readOnly = true)
    public GroupDTO get(Long id, String tenantId) {
        return GroupDTO.from(requireGroup(id, tenantId));
    }

    @Transactional
    public GroupDTO create(GroupDTO request, String tenantId) {
        if (groupRepository.existsByNameAndTenantId(request.name(), tenantId)) {
            throw new ConflictException("Group already exists: " + request.name());
        }
        Group group = Group.builder()
                .name(request.name())
                .description(request.description())
                .tenantId(tenantId)
                .build();
        if (request.roles() != null) {
            group.setRoles(resolveRoles(request.roles()));
        }
        return GroupDTO.from(groupRepository.save(group));
    }

    @Transactional
    public GroupDTO updateRoles(Long id, Set<String> roleNames, String tenantId) {
        Group group = requireGroup(id, tenantId);
        group.setRoles(resolveRoles(roleNames));
        return GroupDTO.from(groupRepository.save(group));
    }

    @Transactional
    public void delete(Long id, String tenantId) {
        Group group = requireGroup(id, tenantId);
        groupRepository.delete(group);
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        Set<Role> roles = new HashSet<>();
        for (String name : roleNames) {
            roles.add(roleRepository.findByName(name)
                    .orElseThrow(() -> new NotFoundException("Role not found: " + name)));
        }
        return roles;
    }

    private Group requireGroup(Long id, String tenantId) {
        return groupRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new NotFoundException("Group not found."));
    }
}
