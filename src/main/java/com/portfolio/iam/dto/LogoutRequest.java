package com.portfolio.iam.dto;

/**
 * Optional logout payload. When a refresh token is supplied it is revoked in
 * addition to the current access token (identified from the bearer header).
 */
public record LogoutRequest(String refreshToken) {
}
