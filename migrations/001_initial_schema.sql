-- Migration: 001_initial_schema
-- Description: Create initial schema for identity service
-- Date: 2026-01-23

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'inactive', 'suspended'))
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roles_name ON roles(name);

-- Permissions table
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    module VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_permissions_code ON permissions(code);
CREATE INDEX idx_permissions_module ON permissions(module);

-- Role permissions (many-to-many)
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- User roles (many-to-many)
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- User entity access (multi-tenant)
CREATE TABLE user_entities (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, entity_id)
);

CREATE INDEX idx_user_entities_user_id ON user_entities(user_id);
CREATE INDEX idx_user_entities_entity_id ON user_entities(entity_id);

-- Refresh tokens
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Audit log for authentication events
CREATE TABLE auth_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_log_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_auth_audit_log_event_type ON auth_audit_log(event_type);
CREATE INDEX idx_auth_audit_log_created_at ON auth_audit_log(created_at);

-- Insert default permissions
INSERT INTO permissions (code, name, description, module) VALUES
    -- User management
    ('user.create', 'Create User', 'Create new users', 'identity'),
    ('user.read', 'Read User', 'View user details', 'identity'),
    ('user.update', 'Update User', 'Update user information', 'identity'),
    ('user.delete', 'Delete User', 'Delete users', 'identity'),

    -- Role management
    ('role.create', 'Create Role', 'Create new roles', 'identity'),
    ('role.read', 'Read Role', 'View role details', 'identity'),
    ('role.update', 'Update Role', 'Update role information', 'identity'),
    ('role.delete', 'Delete Role', 'Delete roles', 'identity'),

    -- GL permissions
    ('gl.account.create', 'Create GL Account', 'Create chart of accounts', 'gl'),
    ('gl.account.read', 'Read GL Account', 'View accounts', 'gl'),
    ('gl.account.update', 'Update GL Account', 'Update accounts', 'gl'),
    ('gl.journal.create', 'Create Journal Entry', 'Create journal entries', 'gl'),
    ('gl.journal.read', 'Read Journal Entry', 'View journal entries', 'gl'),
    ('gl.journal.post', 'Post Journal Entry', 'Post journal entries to GL', 'gl'),

    -- AP permissions
    ('ap.vendor.create', 'Create Vendor', 'Create vendors', 'ap'),
    ('ap.vendor.read', 'Read Vendor', 'View vendors', 'ap'),
    ('ap.vendor.update', 'Update Vendor', 'Update vendors', 'ap'),
    ('ap.invoice.create', 'Create AP Invoice', 'Create AP invoices', 'ap'),
    ('ap.invoice.read', 'Read AP Invoice', 'View AP invoices', 'ap'),
    ('ap.invoice.approve', 'Approve AP Invoice', 'Approve AP invoices', 'ap'),
    ('ap.invoice.post', 'Post AP Invoice', 'Post invoices to GL', 'ap');

-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('Super Admin', 'Full system access'),
    ('Accountant', 'Full GL and financial access'),
    ('AP Clerk', 'Accounts Payable data entry'),
    ('AP Manager', 'Accounts Payable management and approvals'),
    ('Viewer', 'Read-only access to financial data');

-- Assign permissions to Super Admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Super Admin';

-- Assign GL permissions to Accountant role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Accountant'
AND p.module IN ('gl', 'identity')
AND p.code LIKE '%.read';

-- Assign AP permissions to AP Clerk role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'AP Clerk'
AND p.module = 'ap'
AND p.code IN ('ap.vendor.read', 'ap.invoice.create', 'ap.invoice.read');

-- Assign AP permissions to AP Manager role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'AP Manager'
AND p.module = 'ap';

-- Assign read permissions to Viewer role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Viewer'
AND p.code LIKE '%.read';

-- Comments
COMMENT ON TABLE users IS 'User accounts and authentication';
COMMENT ON TABLE roles IS 'User roles for RBAC';
COMMENT ON TABLE permissions IS 'System permissions';
COMMENT ON TABLE role_permissions IS 'Role to permission assignments';
COMMENT ON TABLE user_roles IS 'User to role assignments';
COMMENT ON TABLE user_entities IS 'User access to entities (multi-tenant)';
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens';
COMMENT ON TABLE auth_audit_log IS 'Authentication event audit trail';
