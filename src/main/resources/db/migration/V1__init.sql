-- =====================================================================
-- IAM Service — initial schema
-- =====================================================================

CREATE TABLE roles (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255),
    CONSTRAINT uk_role_name UNIQUE (name)
);

CREATE TABLE groups (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    description VARCHAR(255),
    tenant_id   VARCHAR(64)  NOT NULL,
    CONSTRAINT uk_group_name_tenant UNIQUE (name, tenant_id)
);

CREATE TABLE users (
    id                    BIGSERIAL PRIMARY KEY,
    email                 VARCHAR(255) NOT NULL,
    password_hash         VARCHAR(100) NOT NULL,
    full_name             VARCHAR(255),
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    locked                BOOLEAN      NOT NULL DEFAULT FALSE,
    two_factor_enabled    BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_secret           VARCHAR(128),
    tenant_id             VARCHAR(64)  NOT NULL,
    failed_login_attempts INT          NOT NULL DEFAULT 0,
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL,
    updated_at            TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uk_user_email_tenant UNIQUE (email, tenant_id)
);

CREATE INDEX idx_users_tenant ON users (tenant_id);

-- Join tables ---------------------------------------------------------

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE user_groups (
    user_id  BIGINT NOT NULL,
    group_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, group_id),
    CONSTRAINT fk_user_groups_user  FOREIGN KEY (user_id)  REFERENCES users (id)  ON DELETE CASCADE,
    CONSTRAINT fk_user_groups_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
);

CREATE TABLE group_roles (
    group_id BIGINT NOT NULL,
    role_id  BIGINT NOT NULL,
    PRIMARY KEY (group_id, role_id),
    CONSTRAINT fk_group_roles_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_group_roles_role  FOREIGN KEY (role_id)  REFERENCES roles (id)  ON DELETE CASCADE
);

-- Tokens --------------------------------------------------------------

CREATE TABLE refresh_token (
    id          BIGSERIAL PRIMARY KEY,
    token_hash  VARCHAR(64)  NOT NULL,
    user_id     BIGINT       NOT NULL,
    tenant_id   VARCHAR(64)  NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    revoked     BOOLEAN      NOT NULL DEFAULT FALSE,
    device_info VARCHAR(512),
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uk_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_token_hash ON refresh_token (token_hash);
CREATE INDEX idx_refresh_user       ON refresh_token (user_id);

CREATE TABLE revoked_access_token (
    id         BIGSERIAL PRIMARY KEY,
    jti        VARCHAR(64)  NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uk_revoked_jti UNIQUE (jti)
);

CREATE INDEX idx_revoked_jti ON revoked_access_token (jti);

-- Audit ---------------------------------------------------------------

CREATE TABLE audit_event (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  VARCHAR(64),
    user_id    BIGINT,
    action     VARCHAR(32) NOT NULL,
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    details    JSONB,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_audit_tenant  ON audit_event (tenant_id);
CREATE INDEX idx_audit_user    ON audit_event (user_id);
CREATE INDEX idx_audit_created ON audit_event (created_at);
