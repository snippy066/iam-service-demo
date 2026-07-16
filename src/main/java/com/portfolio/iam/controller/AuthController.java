package com.portfolio.iam.controller;

import com.portfolio.iam.dto.LoginRequest;
import com.portfolio.iam.dto.LogoutRequest;
import com.portfolio.iam.dto.RefreshRequest;
import com.portfolio.iam.dto.RegisterRequest;
import com.portfolio.iam.dto.TokenResponse;
import com.portfolio.iam.dto.UserDTO;
import com.portfolio.iam.security.AuthenticatedUser;
import com.portfolio.iam.security.CurrentUser;
import com.portfolio.iam.security.TenantContext;
import com.portfolio.iam.service.AuthService;
import com.portfolio.iam.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public authentication endpoints plus the authenticated {@code /me} lookup.
 *
 * <p>Cookie option: for browser clients the refresh token returned by
 * {@code /login} and {@code /refresh} can instead be delivered as an
 * {@code HttpOnly; Secure; SameSite=Strict} cookie; {@code /refresh} would then
 * read it from that cookie rather than the request body.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Registration, login, token refresh and logout")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    @Operation(summary = "Register a new user", description = "Creates a self-service account with ROLE_USER.")
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserDTO register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request, TenantContext.getTenantId());
    }

    @Operation(summary = "Log in", description = "Verifies credentials (and TOTP if 2FA is enabled) and "
            + "returns an access + refresh token pair.")
    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        return authService.login(request, TenantContext.getTenantId(), servletRequest.getHeader("User-Agent"));
    }

    @Operation(summary = "Refresh tokens", description = "Rotates the refresh token and issues a new token pair.")
    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest servletRequest) {
        return authService.refresh(request.refreshToken(), servletRequest.getHeader("User-Agent"));
    }

    @Operation(summary = "Log out", description = "Revokes the current access token and an optional refresh token.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestBody(required = false) LogoutRequest request) {
        AuthenticatedUser principal = CurrentUser.require();
        String refreshToken = request != null ? request.refreshToken() : null;
        authService.logout(principal, refreshToken);
    }

    @Operation(summary = "Current user", description = "Returns the profile of the authenticated user.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @GetMapping("/me")
    public ResponseEntity<UserDTO> me() {
        AuthenticatedUser principal = CurrentUser.require();
        return ResponseEntity.ok(userService.get(principal.userId(), principal.tenantId()));
    }
}
