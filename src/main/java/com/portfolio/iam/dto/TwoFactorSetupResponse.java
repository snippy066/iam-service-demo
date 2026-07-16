package com.portfolio.iam.dto;

/**
 * Result of initiating 2FA setup.
 *
 * @param secret      Base32 shared secret to store in an authenticator app
 * @param otpauthUri  {@code otpauth://} provisioning URI
 * @param qrCodeDataUri PNG QR-code encoded as a {@code data:} URI for display
 */
public record TwoFactorSetupResponse(String secret, String otpauthUri, String qrCodeDataUri) {
}
