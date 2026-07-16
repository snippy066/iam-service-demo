package com.portfolio.iam.domain.entity;

/**
 * Enumeration of security-relevant actions recorded in the audit log.
 */
public enum AuditAction {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    TOKEN_REFRESH,
    PASSWORD_CHANGE,
    TWO_FA_ENABLED,
    TWO_FA_DISABLED,
    USER_CREATED,
    USER_UPDATED,
    USER_DELETED,
    USER_LOCKED,
    USER_UNLOCKED,
    ROLE_ASSIGNED,
    ROLE_REVOKED,
    GROUP_ASSIGNED,
    GROUP_REVOKED
}
