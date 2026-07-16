package com.portfolio.iam.security;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.portfolio.iam.repository.RevokedAccessTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates the {@code Authorization: Bearer} access token on each request:
 * verifies the signature/expiry, rejects revoked tokens (by {@code jti}) and
 * populates the {@code SecurityContext} plus {@link TenantContext}. Requests
 * without a bearer token pass through unauthenticated (public endpoints are
 * allowed by {@link SecurityConfig}; protected ones are rejected downstream).
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final RevokedAccessTokenRepository revokedAccessTokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   RevokedAccessTokenRepository revokedAccessTokenRepository) {
        this.jwtService = jwtService;
        this.revokedAccessTokenRepository = revokedAccessTokenRepository;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith(BEARER_PREFIX)
                    && SecurityContextHolder.getContext().getAuthentication() == null) {
                String token = header.substring(BEARER_PREFIX.length()).trim();
                authenticate(token, request);
            }
            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private void authenticate(String token, HttpServletRequest request) {
        try {
            AuthenticatedUser principal = jwtService.parse(token);
            if (revokedAccessTokenRepository.existsByJti(principal.jti())) {
                return; // token was explicitly revoked (logout) — treat as unauthenticated
            }
            List<SimpleGrantedAuthority> authorities = principal.roles().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList();
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            TenantContext.set(principal.tenantId());
        } catch (JWTVerificationException | IllegalArgumentException ex) {
            SecurityContextHolder.clearContext();
        }
    }
}
