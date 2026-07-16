package com.portfolio.iam.controller;

import com.portfolio.iam.dto.Disable2faRequest;
import com.portfolio.iam.dto.Enable2faRequest;
import com.portfolio.iam.dto.TwoFactorSetupResponse;
import com.portfolio.iam.security.CurrentUser;
import com.portfolio.iam.service.TwoFactorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * TOTP two-factor authentication lifecycle for the authenticated user.
 */
@RestController
@RequestMapping("/api/v1/2fa")
@Tag(name = "Two-Factor Authentication", description = "TOTP setup, enable and disable")
@SecurityRequirement(name = "bearerAuth")
public class TwoFactorController {

    private final TwoFactorService twoFactorService;

    public TwoFactorController(TwoFactorService twoFactorService) {
        this.twoFactorService = twoFactorService;
    }

    @Operation(summary = "Begin 2FA setup", description = "Generates a TOTP secret and provisioning QR code. "
            + "2FA is not active until /enable succeeds.")
    @PostMapping("/setup")
    public TwoFactorSetupResponse setup() {
        return twoFactorService.setup(CurrentUser.require());
    }

    @Operation(summary = "Enable 2FA", description = "Confirms setup by verifying a TOTP code.")
    @PostMapping("/enable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void enable(@Valid @RequestBody Enable2faRequest request) {
        twoFactorService.enable(CurrentUser.require(), request.totpCode());
    }

    @Operation(summary = "Disable 2FA", description = "Verifies a current TOTP code, then disables 2FA.")
    @PostMapping("/disable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void disable(@Valid @RequestBody Disable2faRequest request) {
        twoFactorService.disable(CurrentUser.require(), request.totpCode());
    }
}
