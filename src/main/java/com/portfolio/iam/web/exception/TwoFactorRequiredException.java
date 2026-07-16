package com.portfolio.iam.web.exception;

/** Thrown during login when the account has 2FA enabled but no valid TOTP code was supplied. */
public class TwoFactorRequiredException extends RuntimeException {

    public TwoFactorRequiredException(String message) {
        super(message);
    }
}
