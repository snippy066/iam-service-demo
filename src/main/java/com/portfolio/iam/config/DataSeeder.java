package com.portfolio.iam.config;

import com.portfolio.iam.domain.entity.Role;
import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.repository.RoleRepository;
import com.portfolio.iam.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds a demo tenant, the baseline roles and a demo admin user. Active ONLY
 * under the {@code seed} or {@code dev} profiles. The admin credentials come
 * from configuration and are strictly for local demos — never real secrets.
 */
@Component
@Profile({"seed", "dev"})
public class DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AppProperties properties;

    public DataSeeder(UserRepository userRepository,
                      RoleRepository roleRepository,
                      PasswordEncoder passwordEncoder,
                      AppProperties properties) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    @Override
    @Transactional
    public void run(String... args) {
        AppProperties.Seed seed = properties.seed();
        if (seed == null || !seed.enabled()) {
            return;
        }

        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(Role.builder()
                        .name("ROLE_ADMIN").description("Administrator").build()));
        roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(Role.builder()
                        .name("ROLE_USER").description("Standard user").build()));

        String tenantId = seed.tenantId();
        if (userRepository.existsByEmailAndTenantId(seed.adminEmail(), tenantId)) {
            log.info("Demo admin already present for tenant '{}'.", tenantId);
            return;
        }

        User admin = User.builder()
                .email(seed.adminEmail())
                .passwordHash(passwordEncoder.encode(seed.adminPassword()))
                .fullName("Demo Administrator")
                .tenantId(tenantId)
                .enabled(true)
                .build();
        admin.getRoles().add(adminRole);
        userRepository.save(admin);

        log.warn("Seeded DEMO admin '{}' in tenant '{}'. Change or disable seeding before any real deployment.",
                seed.adminEmail(), tenantId);
    }
}
