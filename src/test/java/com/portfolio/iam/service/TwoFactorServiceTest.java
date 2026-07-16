package com.portfolio.iam.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.dto.TwoFactorSetupResponse;
import com.portfolio.iam.repository.UserRepository;
import com.portfolio.iam.security.AuthenticatedUser;
import com.portfolio.iam.web.exception.UnauthorizedException;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TwoFactorServiceTest {

    private static final String TENANT = "primary";

    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;

    private TwoFactorService twoFactorService;

    @BeforeEach
    void setUp() {
        twoFactorService = new TwoFactorService(userRepository, auditService);
    }

    private AuthenticatedUser principal() {
        return new AuthenticatedUser(1L, "bob@example.com", TENANT, "jti", Set.of("ROLE_USER"));
    }

    private String validCodeFor(String secret) throws CodeGenerationException {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        long counter = Math.floorDiv(timeProvider.getTime(), 30);
        return codeGenerator.generate(secret, counter);
    }

    @Test
    void verifyCode_acceptsValidCode() throws Exception {
        String secret = new DefaultSecretGenerator().generate();
        assertThat(twoFactorService.verifyCode(secret, validCodeFor(secret))).isTrue();
    }

    @Test
    void verifyCode_rejectsInvalidCode() {
        String secret = new DefaultSecretGenerator().generate();
        assertThat(twoFactorService.verifyCode(secret, "000000")).isFalse();
        assertThat(twoFactorService.verifyCode(secret, null)).isFalse();
    }

    @Test
    void setup_generatesSecretAndProvisioningData() {
        User user = User.builder().id(1L).email("bob@example.com").tenantId(TENANT).build();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TwoFactorSetupResponse response = twoFactorService.setup(principal());

        assertThat(response.secret()).isNotBlank();
        assertThat(response.otpauthUri()).startsWith("otpauth://totp/");
        assertThat(response.qrCodeDataUri()).startsWith("data:image/png;base64,");
        assertThat(user.getTotpSecret()).isEqualTo(response.secret());
        assertThat(user.isTwoFactorEnabled()).isFalse(); // not active until enable()
    }

    @Test
    void enable_activatesWithValidCode() throws Exception {
        String secret = new DefaultSecretGenerator().generate();
        User user = User.builder().id(1L).email("bob@example.com").tenantId(TENANT).totpSecret(secret).build();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        twoFactorService.enable(principal(), validCodeFor(secret));

        assertThat(user.isTwoFactorEnabled()).isTrue();
    }

    @Test
    void enable_rejectsInvalidCode() {
        String secret = new DefaultSecretGenerator().generate();
        User user = User.builder().id(1L).email("bob@example.com").tenantId(TENANT).totpSecret(secret).build();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> twoFactorService.enable(principal(), "000000"))
                .isInstanceOf(UnauthorizedException.class);
        assertThat(user.isTwoFactorEnabled()).isFalse();
    }

    @Test
    void disable_requiresEnabled() {
        User user = User.builder().id(1L).email("bob@example.com").tenantId(TENANT).build();
        when(userRepository.findByIdAndTenantId(1L, TENANT)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> twoFactorService.disable(principal(), "000000"))
                .isInstanceOf(UnauthorizedException.class);
    }
}
