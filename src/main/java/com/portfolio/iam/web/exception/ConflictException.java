package com.portfolio.iam.web.exception;

/** Thrown when an operation conflicts with existing state (e.g. duplicate email). */
public class ConflictException extends RuntimeException {

    public ConflictException(String message) {
        super(message);
    }
}
