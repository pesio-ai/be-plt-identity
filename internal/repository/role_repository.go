package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pesio-ai/be-lib-common/logger"
)

type RoleRepository struct {
	db  *pgxpool.Pool
	log *logger.Logger
}

func NewRoleRepository(db *pgxpool.Pool, log *logger.Logger) *RoleRepository {
	return &RoleRepository{
		db:  db,
		log: log,
	}
}

// Create creates a new role
func (r *RoleRepository) Create(ctx context.Context, role *Role) error {
	role.ID = uuid.New().String()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	query := `
		INSERT INTO roles (
			id, entity_id, name, display_name, description,
			role_type, is_active, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`

	_, err := r.db.Exec(ctx, query,
		role.ID, role.EntityID, role.Name, role.DisplayName, role.Description,
		role.RoleType, role.IsActive, role.CreatedAt, role.UpdatedAt, role.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// GetByID retrieves a role by ID
func (r *RoleRepository) GetByID(ctx context.Context, id string) (*Role, error) {
	role := &Role{}

	query := `
		SELECT id, entity_id, name, display_name, description,
			   role_type, is_active, created_at, updated_at, created_by, updated_by
		FROM roles
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.EntityID, &role.Name, &role.DisplayName, &role.Description,
		&role.RoleType, &role.IsActive, &role.CreatedAt, &role.UpdatedAt,
		&role.CreatedBy, &role.UpdatedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}

// List retrieves roles for an entity
func (r *RoleRepository) List(ctx context.Context, entityID *string, activeOnly bool) ([]*Role, error) {
	query := `
		SELECT id, entity_id, name, display_name, description,
			   role_type, is_active, created_at, updated_at, created_by, updated_by
		FROM roles
		WHERE (entity_id = $1 OR entity_id IS NULL)
	`

	args := []interface{}{entityID}

	if activeOnly {
		query += " AND is_active = true"
	}

	query += " ORDER BY role_type, name"

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(
			&role.ID, &role.EntityID, &role.Name, &role.DisplayName, &role.Description,
			&role.RoleType, &role.IsActive, &role.CreatedAt, &role.UpdatedAt,
			&role.CreatedBy, &role.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// AssignToUser assigns a role to a user
func (r *RoleRepository) AssignToUser(ctx context.Context, userID, roleID, entityID, assignedBy string) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, entity_id, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, role_id, entity_id) DO NOTHING
	`

	_, err := r.db.Exec(ctx, query, userID, roleID, entityID, time.Now(), assignedBy)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// UnassignFromUser removes a role from a user
func (r *RoleRepository) UnassignFromUser(ctx context.Context, userID, roleID, entityID string) error {
	query := `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2 AND entity_id = $3
	`

	result, err := r.db.Exec(ctx, query, userID, roleID, entityID)
	if err != nil {
		return fmt.Errorf("failed to unassign role: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("role assignment not found")
	}

	return nil
}

// GetUserRoles retrieves roles assigned to a user for an entity
func (r *RoleRepository) GetUserRoles(ctx context.Context, userID, entityID string) ([]*Role, error) {
	query := `
		SELECT r.id, r.entity_id, r.name, r.display_name, r.description,
			   r.role_type, r.is_active, r.created_at, r.updated_at,
			   r.created_by, r.updated_by
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.entity_id = $2 AND r.is_active = true
		ORDER BY r.role_type, r.name
	`

	rows, err := r.db.Query(ctx, query, userID, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(
			&role.ID, &role.EntityID, &role.Name, &role.DisplayName, &role.Description,
			&role.RoleType, &role.IsActive, &role.CreatedAt, &role.UpdatedAt,
			&role.CreatedBy, &role.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// GetUserIDsByRoleName returns user IDs assigned to a role by name for an entity
func (r *RoleRepository) GetUserIDsByRoleName(ctx context.Context, entityID, roleName string) ([]string, error) {
	query := `
		SELECT ur.user_id
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE r.entity_id = $1 AND r.name = $2 AND r.is_active = true
	`

	rows, err := r.db.Query(ctx, query, entityID, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by role name: %w", err)
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("failed to scan user id: %w", err)
		}
		userIDs = append(userIDs, userID)
	}

	return userIDs, nil
}

// GetRolePermissions retrieves permissions for a role
func (r *RoleRepository) GetRolePermissions(ctx context.Context, roleID string) ([]*Permission, error) {
	query := `
		SELECT p.id, p.module, p.resource, p.action, p.name, p.description, p.is_sensitive, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.module, p.resource, p.action
	`

	rows, err := r.db.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		perm := &Permission{}
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action,
			&perm.Name, &perm.Description, &perm.IsSensitive, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GetUserPermissions retrieves all permissions for a user (aggregated from all their roles)
func (r *RoleRepository) GetUserPermissions(ctx context.Context, userID, entityID string) ([]*Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.module, p.resource, p.action, p.name, p.description, p.is_sensitive, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		INNER JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND ur.entity_id = $2 AND r.is_active = true
		ORDER BY p.module, p.resource, p.action
	`

	rows, err := r.db.Query(ctx, query, userID, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		perm := &Permission{}
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action,
			&perm.Name, &perm.Description, &perm.IsSensitive, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// CheckUserPermission checks if a user has a specific permission
func (r *RoleRepository) CheckUserPermission(ctx context.Context, userID, entityID, module, resource, action string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM permissions p
			INNER JOIN role_permissions rp ON p.id = rp.permission_id
			INNER JOIN user_roles ur ON rp.role_id = ur.role_id
			INNER JOIN roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1 
			  AND ur.entity_id = $2
			  AND r.is_active = true
			  AND p.module = $3
			  AND p.resource = $4
			  AND p.action = $5
		)
	`

	var hasPermission bool
	err := r.db.QueryRow(ctx, query, userID, entityID, module, resource, action).Scan(&hasPermission)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return hasPermission, nil
}
