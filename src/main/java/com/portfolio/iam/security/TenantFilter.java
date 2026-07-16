package com.portfolio.iam.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.lang.NonNull;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the tenant for unauthenticated public endpoints (registration, login)
 * from the {@code X-Tenant-Id} header, before the JWT filter runs. For
 * authenticated requests the tenant from the token takes precedence.
 */
public class TenantFilter extends OncePerRequestFilter {

    public static final String TENANT_HEADER = "X-Tenant-Id";

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String tenant = request.getHeader(TENANT_HEADER);
        if (StringUtils.hasText(tenant)) {
            TenantContext.set(tenant.trim());
        }
        filterChain.doFilter(request, response);
    }
}
