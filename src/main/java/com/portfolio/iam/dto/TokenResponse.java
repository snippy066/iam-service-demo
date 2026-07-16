package com.portfolio.iam.dto;

/**
 * Issued token pair.
 *
 * <p>For simplicity the refresh token is returned in the body. In a browser
 * deployment it is recommended to instead set the refresh token in a
 * {@code HttpOnly; Secure; SameSite=Strict} cookie and omit it here — the
 * server side already supports this (see {@code AuthController} docs).
 *
 * @param accessToken  short-lived signed JWT
 * @param refreshToken opaque rotating refresh token (store securely)
 * @param tokenType    always {@code Bearer}
 * @param expiresIn    access token lifetime in seconds
 */
public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn) {

    public static TokenResponse bearer(String accessToken, String refreshToken, long expiresIn) {
        return new TokenResponse(accessToken, refreshToken, "Bearer", expiresIn);
    }
}
