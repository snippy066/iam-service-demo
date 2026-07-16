package com.portfolio.iam.security;

import com.portfolio.iam.web.exception.UnauthorizedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/** Convenience accessor for the authenticated principal in the current context. */
public final class CurrentUser {

    private CurrentUser() {
    }

    /**
     * @return the authenticated principal
     * @throws UnauthorizedException if there is no authenticated user
     */
    public static AuthenticatedUser require() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof AuthenticatedUser principal)) {
            throw new UnauthorizedException("No authenticated user in the security context.");
        }
        return principal;
    }
}
