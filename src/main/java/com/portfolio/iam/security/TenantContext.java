package com.portfolio.iam.security;

/**
 * Holds the tenant id for the current request on a {@link ThreadLocal}. Populated
 * by {@link TenantFilter} / {@link JwtAuthenticationFilter} and cleared at the end
 * of every request to prevent leakage across pooled threads.
 */
public final class TenantContext {

    public static final String DEFAULT_TENANT = "primary";

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TenantContext() {
    }

    public static void set(String tenantId) {
        CURRENT.set(tenantId);
    }

    /** @return the current tenant id, or {@link #DEFAULT_TENANT} when none is set. */
    public static String getTenantId() {
        String value = CURRENT.get();
        return value != null ? value : DEFAULT_TENANT;
    }

    public static boolean isSet() {
        return CURRENT.get() != null;
    }

    public static void clear() {
        CURRENT.remove();
    }
}
