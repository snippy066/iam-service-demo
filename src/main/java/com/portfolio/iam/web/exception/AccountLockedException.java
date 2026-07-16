package com.portfolio.iam.web.exception;

/** Thrown when authentication is attempted against a locked or disabled account. */
public class AccountLockedException extends RuntimeException {

    public AccountLockedException(String message) {
        super(message);
    }
}
