-- Baseline roles used across all tenants.
INSERT INTO roles (name, description) VALUES
    ('ROLE_ADMIN', 'Administrator with full access'),
    ('ROLE_USER',  'Standard authenticated user')
ON CONFLICT (name) DO NOTHING;
