package com.portfolio.iam.dto;

import jakarta.validation.constraints.NotBlank;

/** Confirms 2FA setup by proving possession of the shared secret. */
public record Enable2faRequest(@NotBlank String totpCode) {
}
