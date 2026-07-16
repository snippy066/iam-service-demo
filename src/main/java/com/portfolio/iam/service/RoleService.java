package com.portfolio.iam.service;

import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.dto.RoleDTO;
import com.portfolio.iam.repository.RoleRepository;
import com.portfolio.iam.web.exception.ConflictException;
import com.portfolio.iam.web.exception.NotFoundException;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Administration of the global role catalog. */
@Service
public class RoleService {

    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Transactional(readOnly = true)
    public List<RoleDTO> list() {
        return roleRepository.findAll().stream().map(RoleDTO::from).toList();
    }

    @Transactional
    public RoleDTO create(RoleDTO request) {
        if (roleRepository.existsByName(request.name())) {
            throw new ConflictException("Role already exists: " + request.name());
        }
        Role role = roleRepository.save(Role.builder()
                .name(request.name())
                .description(request.description())
                .build());
        return RoleDTO.from(role);
    }

    @Transactional
    public void delete(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Role not found."));
        roleRepository.delete(role);
    }
}
