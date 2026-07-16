package com.portfolio.iam.web.exception;

/** Thrown when authentication fails (bad credentials, invalid/expired token). */
public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String message) {
        super(message);
    }
}
