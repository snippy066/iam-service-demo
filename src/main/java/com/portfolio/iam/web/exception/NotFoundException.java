package com.portfolio.iam.web.exception;

/** Thrown when a requested resource does not exist (or is not visible to the tenant). */
public class NotFoundException extends RuntimeException {

    public NotFoundException(String message) {
        super(message);
    }
}
