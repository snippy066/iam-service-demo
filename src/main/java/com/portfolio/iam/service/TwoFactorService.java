package com.portfolio.iam.service;

import com.portfolio.iam.domain.entity.AuditAction;
import com.portfolio.iam.domain.entity.User;
import com.portfolio.iam.dto.TwoFactorSetupResponse;
import com.portfolio.iam.repository.UserRepository;
import com.portfolio.iam.security.AuthenticatedUser;
import com.portfolio.iam.web.exception.NotFoundException;
import com.portfolio.iam.web.exception.UnauthorizedException;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * TOTP-based two-factor authentication: secret generation, QR provisioning and
 * code verification (RFC 6238, compatible with Google Authenticator / Authy).
 */
@Service
public class TwoFactorService {

    private static final String ISSUER = "IAM Service";

    private final UserRepository userRepository;
    private final AuditService auditService;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final CodeVerifier codeVerifier;

    public TwoFactorService(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        // Allow one 30s step of clock drift on either side.
        verifier.setAllowedTimePeriodDiscrepancy(1);
        this.codeVerifier = verifier;
    }

    /**
     * Generates and stores a fresh TOTP secret for the current user and returns
     * the provisioning data. 2FA is not active until {@link #enable} succeeds.
     */
    @Transactional
    public TwoFactorSetupResponse setup(AuthenticatedUser principal) {
        User user = loadUser(principal);
        String secret = secretGenerator.generate();
        user.setTotpSecret(secret);
        userRepository.save(user);

        QrData data = new QrData.Builder()
                .label(user.getEmail())
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        String qrDataUri = generateQrDataUri(data);
        return new TwoFactorSetupResponse(secret, data.getUri(), qrDataUri);
    }

    /** Verifies the supplied code against the stored secret and activates 2FA. */
    @Transactional
    public void enable(AuthenticatedUser principal, String totpCode) {
        User user = loadUser(principal);
        if (user.getTotpSecret() == null) {
            throw new UnauthorizedException("Two-factor setup has not been initiated.");
        }
        if (!verifyCode(user.getTotpSecret(), totpCode)) {
            throw new UnauthorizedException("Invalid two-factor code.");
        }
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        auditService.record(user.getTenantId(), user.getId(), AuditAction.TWO_FA_ENABLED, Map.of());
    }

    /** Re-verifies a current code, then disables 2FA and clears the secret. */
    @Transactional
    public void disable(AuthenticatedUser principal, String totpCode) {
        User user = loadUser(principal);
        if (!user.isTwoFactorEnabled() || user.getTotpSecret() == null) {
            throw new UnauthorizedException("Two-factor authentication is not enabled.");
        }
        if (!verifyCode(user.getTotpSecret(), totpCode)) {
            throw new UnauthorizedException("Invalid two-factor code.");
        }
        user.setTwoFactorEnabled(false);
        user.setTotpSecret(null);
        userRepository.save(user);
        auditService.record(user.getTenantId(), user.getId(), AuditAction.TWO_FA_DISABLED, Map.of());
    }

    /** @return true if {@code code} is a currently-valid TOTP for {@code secret}. */
    public boolean verifyCode(String secret, String code) {
        return code != null && codeVerifier.isValidCode(secret, code);
    }

    private String generateQrDataUri(QrData data) {
        try {
            QrGenerator generator = new ZxingPngQrGenerator();
            byte[] image = generator.generate(data);
            return Utils.getDataUriForImage(image, generator.getImageMimeType());
        } catch (QrGenerationException e) {
            throw new IllegalStateException("Failed to generate 2FA QR code.", e);
        }
    }

    private User loadUser(AuthenticatedUser principal) {
        return userRepository.findByIdAndTenantId(principal.userId(), principal.tenantId())
                .orElseThrow(() -> new NotFoundException("User not found."));
    }
}
