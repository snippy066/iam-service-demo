package com.portfolio.iam.dto;

import jakarta.validation.constraints.NotBlank;

/** Payload to exchange a valid refresh token for a rotated token pair. */
public record RefreshRequest(@NotBlank String refreshToken) {
}
