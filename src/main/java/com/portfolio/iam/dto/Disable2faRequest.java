package com.portfolio.iam.dto;

import jakarta.validation.constraints.NotBlank;

/** Disables 2FA after re-verifying a current TOTP code. */
public record Disable2faRequest(@NotBlank String totpCode) {
}
