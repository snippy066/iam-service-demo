package com.portfolio.iam.web;

import com.portfolio.iam.web.exception.AccountLockedException;
import com.portfolio.iam.web.exception.ConflictException;
import com.portfolio.iam.web.exception.NotFoundException;
import com.portfolio.iam.web.exception.TwoFactorRequiredException;
import com.portfolio.iam.web.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates application exceptions into RFC-7807 {@link ProblemDetail} responses
 * with stable, machine-readable {@code type} URIs so clients can branch on the
 * failure mode (e.g. distinguishing "2FA required" from "bad credentials").
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String BASE_TYPE = "https://portfolio.iam/problems/";

    @ExceptionHandler({BadCredentialsException.class, UnauthorizedException.class})
    public ProblemDetail handleUnauthorized(RuntimeException ex, HttpServletRequest request) {
        return build(HttpStatus.UNAUTHORIZED, "invalid-credentials", "Authentication failed",
                ex.getMessage(), request);
    }

    @ExceptionHandler(TwoFactorRequiredException.class)
    public ProblemDetail handleTwoFactorRequired(TwoFactorRequiredException ex, HttpServletRequest request) {
        ProblemDetail pd = build(HttpStatus.UNAUTHORIZED, "two-factor-required",
                "Two-factor authentication required", ex.getMessage(), request);
        pd.setProperty("twoFactorRequired", true);
        return pd;
    }

    @ExceptionHandler(AccountLockedException.class)
    public ProblemDetail handleLocked(AccountLockedException ex, HttpServletRequest request) {
        return build(HttpStatus.LOCKED, "account-locked", "Account locked", ex.getMessage(), request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        return build(HttpStatus.FORBIDDEN, "access-denied", "Access denied",
                "You do not have permission to perform this action.", request);
    }

    @ExceptionHandler(NotFoundException.class)
    public ProblemDetail handleNotFound(NotFoundException ex, HttpServletRequest request) {
        return build(HttpStatus.NOT_FOUND, "not-found", "Resource not found", ex.getMessage(), request);
    }

    @ExceptionHandler(ConflictException.class)
    public ProblemDetail handleConflict(ConflictException ex, HttpServletRequest request) {
        return build(HttpStatus.CONFLICT, "conflict", "Conflict", ex.getMessage(), request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        ProblemDetail pd = build(HttpStatus.BAD_REQUEST, "validation-error", "Validation failed",
                "One or more fields are invalid.", request);
        List<FieldViolation> violations = new ArrayList<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            violations.add(new FieldViolation(fe.getField(), fe.getDefaultMessage()));
        }
        pd.setProperty("errors", violations);
        return pd;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "bad-request", "Bad request", ex.getMessage(), request);
    }

    private ProblemDetail build(HttpStatus status, String type, String title, String detail,
                                HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setTitle(title);
        pd.setType(URI.create(BASE_TYPE + type));
        pd.setInstance(URI.create(request.getRequestURI()));
        pd.setProperty("timestamp", Instant.now());
        return pd;
    }

    /** Single field validation violation exposed under the {@code errors} member. */
    public record FieldViolation(String field, String message) {
    }
}
