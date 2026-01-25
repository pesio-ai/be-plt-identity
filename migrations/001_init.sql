-- PLT-1: Identity & Access Management - MVP Schema
-- Simplified version focusing on essential authentication and authorization

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255),  -- Argon2id hash, nullable for SSO-only users
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone VARCHAR(50),
    profile_photo_url VARCHAR(500),
    
    -- Preferences
    timezone VARCHAR(50) DEFAULT 'UTC',
    locale VARCHAR(10) DEFAULT 'en-US',
    
    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',
        -- active, suspended, deactivated, pending
    user_type VARCHAR(20) NOT NULL DEFAULT 'internal',
        -- internal, external, service
    
    -- Authentication tracking
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,
    
    CONSTRAINT users_email_entity_unique UNIQUE (email, entity_id)
);

CREATE INDEX idx_users_entity_id ON users(entity_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id UUID,  -- NULL for system-wide roles
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    role_type VARCHAR(20) NOT NULL DEFAULT 'custom',
        -- system, custom
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,
    
    CONSTRAINT roles_name_entity_unique UNIQUE (name, entity_id)
);

CREATE INDEX idx_roles_entity_id ON roles(entity_id);
CREATE INDEX idx_roles_is_active ON roles(is_active);

-- Permissions table
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module VARCHAR(50) NOT NULL,  -- gl, ap, ar, plt, etc.
    resource VARCHAR(100) NOT NULL,  -- accounts, journals, invoices, etc.
    action VARCHAR(50) NOT NULL,  -- create, read, update, delete, approve, post
    name VARCHAR(200) NOT NULL UNIQUE,  -- Full name: module:resource:action
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,  -- Requires extra logging
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT permissions_module_resource_action_unique UNIQUE (module, resource, action)
);

CREATE INDEX idx_permissions_module ON permissions(module);
CREATE INDEX idx_permissions_name ON permissions(name);

-- Role-Permission mapping
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID,
    
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- User-Role mapping
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,  -- Scope of role assignment
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID,
    
    PRIMARY KEY (user_id, role_id, entity_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_entity_id ON user_roles(entity_id);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,
    
    -- Device information
    device_type VARCHAR(20),  -- web, mobile, api
    device_name VARCHAR(200),
    ip_address VARCHAR(50),
    user_agent TEXT,
    
    -- Session lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Refresh token tracking
    refresh_token_hash VARCHAR(255),  -- SHA256 hash of refresh token
    refresh_token_expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_entity_id ON sessions(entity_id);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Insert default system permissions
-- General Ledger permissions
INSERT INTO permissions (module, resource, action, name, description) VALUES
-- Chart of Accounts
('gl', 'accounts', 'create', 'gl:accounts:create', 'Create new GL accounts'),
('gl', 'accounts', 'read', 'gl:accounts:read', 'View GL accounts'),
('gl', 'accounts', 'update', 'gl:accounts:update', 'Update GL accounts'),
('gl', 'accounts', 'delete', 'gl:accounts:delete', 'Delete GL accounts'),
('gl', 'accounts', 'activate', 'gl:accounts:activate', 'Activate/deactivate GL accounts'),

-- Journal Entries
('gl', 'journals', 'create', 'gl:journals:create', 'Create journal entries'),
('gl', 'journals', 'read', 'gl:journals:read', 'View journal entries'),
('gl', 'journals', 'update', 'gl:journals:update', 'Update journal entries'),
('gl', 'journals', 'delete', 'gl:journals:delete', 'Delete journal entries'),
('gl', 'journals', 'post', 'gl:journals:post', 'Post journal entries'),
('gl', 'journals', 'reverse', 'gl:journals:reverse', 'Reverse journal entries'),
('gl', 'journals', 'approve', 'gl:journals:approve', 'Approve journal entries'),

-- Accounts Payable permissions
-- Vendors
('ap', 'vendors', 'create', 'ap:vendors:create', 'Create vendors'),
('ap', 'vendors', 'read', 'ap:vendors:read', 'View vendors'),
('ap', 'vendors', 'update', 'ap:vendors:update', 'Update vendors'),
('ap', 'vendors', 'delete', 'ap:vendors:delete', 'Delete vendors'),
('ap', 'vendors', 'activate', 'ap:vendors:activate', 'Activate/deactivate vendors'),

-- Invoices
('ap', 'invoices', 'create', 'ap:invoices:create', 'Create invoices'),
('ap', 'invoices', 'read', 'ap:invoices:read', 'View invoices'),
('ap', 'invoices', 'update', 'ap:invoices:update', 'Update invoices'),
('ap', 'invoices', 'delete', 'ap:invoices:delete', 'Delete invoices'),
('ap', 'invoices', 'approve', 'ap:invoices:approve', 'Approve invoices'),
('ap', 'invoices', 'post', 'ap:invoices:post', 'Post invoices to GL'),
('ap', 'invoices', 'pay', 'ap:invoices:pay', 'Mark invoices as paid'),

-- Platform permissions
-- Users
('plt', 'users', 'create', 'plt:users:create', 'Create users'),
('plt', 'users', 'read', 'plt:users:read', 'View users'),
('plt', 'users', 'update', 'plt:users:update', 'Update users'),
('plt', 'users', 'delete', 'plt:users:delete', 'Delete users'),

-- Roles
('plt', 'roles', 'create', 'plt:roles:create', 'Create roles'),
('plt', 'roles', 'read', 'plt:roles:read', 'View roles'),
('plt', 'roles', 'update', 'plt:roles:update', 'Update roles'),
('plt', 'roles', 'delete', 'plt:roles:delete', 'Delete roles'),
('plt', 'roles', 'assign', 'plt:roles:assign', 'Assign roles to users');

-- Insert default system roles
-- System Administrator (all permissions)
INSERT INTO roles (entity_id, name, display_name, description, role_type)
VALUES (NULL, 'system_admin', 'System Administrator', 'Full system access with all permissions', 'system');

-- Get the system_admin role ID
DO $$
DECLARE
    admin_role_id UUID;
BEGIN
    SELECT id INTO admin_role_id FROM roles WHERE name = 'system_admin';
    
    -- Grant all permissions to system_admin
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT admin_role_id, id FROM permissions;
END $$;

-- Accountant role (GL and AP read/write, no delete)
INSERT INTO roles (entity_id, name, display_name, description, role_type)
VALUES (NULL, 'accountant', 'Accountant', 'Can manage GL accounts, journals, vendors, and invoices', 'system');

DO $$
DECLARE
    accountant_role_id UUID;
BEGIN
    SELECT id INTO accountant_role_id FROM roles WHERE name = 'accountant';
    
    -- Grant GL and AP permissions (except delete and sensitive operations)
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT accountant_role_id, id FROM permissions
    WHERE (module IN ('gl', 'ap') AND action NOT IN ('delete', 'approve'))
       OR name IN ('plt:users:read', 'plt:roles:read');
END $$;

-- AP Clerk role (invoice and vendor management)
INSERT INTO roles (entity_id, name, display_name, description, role_type)
VALUES (NULL, 'ap_clerk', 'AP Clerk', 'Can manage vendors and invoices', 'system');

DO $$
DECLARE
    ap_clerk_role_id UUID;
BEGIN
    SELECT id INTO ap_clerk_role_id FROM roles WHERE name = 'ap_clerk';
    
    -- Grant AP permissions
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT ap_clerk_role_id, id FROM permissions
    WHERE module = 'ap' AND action NOT IN ('delete', 'approve', 'post', 'pay');
END $$;

-- Viewer role (read-only access)
INSERT INTO roles (entity_id, name, display_name, description, role_type)
VALUES (NULL, 'viewer', 'Viewer', 'Read-only access to financial data', 'system');

DO $$
DECLARE
    viewer_role_id UUID;
BEGIN
    SELECT id INTO viewer_role_id FROM roles WHERE name = 'viewer';
    
    -- Grant read permissions
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT viewer_role_id, id FROM permissions
    WHERE action = 'read';
END $$;
