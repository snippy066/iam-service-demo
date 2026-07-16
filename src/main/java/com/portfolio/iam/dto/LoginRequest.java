package com.portfolio.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Login payload. {@code totpCode} is optional and only consulted when the
 * account has two-factor authentication enabled.
 */
public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        String totpCode) {
}
