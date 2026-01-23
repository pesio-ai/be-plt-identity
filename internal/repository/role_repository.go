package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/pesio-ai/be-go-common/database"
	"github.com/pesio-ai/be-go-common/errors"
)

// Role represents a role entity
type Role struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	CreatedBy   *string
	CreatedAt   string
	UpdatedBy   *string
	UpdatedAt   string
}

// RoleRepository handles role data operations
type RoleRepository struct {
	db *database.DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *database.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create creates a new role
func (r *RoleRepository) Create(ctx context.Context, role *Role) error {
	query := `
		INSERT INTO roles (name, description, created_by)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		role.Name,
		role.Description,
		role.CreatedBy,
	).Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to create role")
	}

	return nil
}

// GetByID retrieves a role by ID
func (r *RoleRepository) GetByID(ctx context.Context, id string) (*Role, error) {
	role := &Role{}

	query := `
		SELECT id, name, description, created_by, created_at, updated_by, updated_at
		FROM roles
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedBy,
		&role.CreatedAt,
		&role.UpdatedBy,
		&role.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, errors.NotFound("role", id)
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get role")
	}

	// Load permissions
	role.Permissions, err = r.getRolePermissions(ctx, id)
	if err != nil {
		return nil, err
	}

	return role, nil
}

// List retrieves all roles with pagination
func (r *RoleRepository) List(ctx context.Context, limit, offset int) ([]*Role, int64, error) {
	// Get total count
	var total int64
	countQuery := `SELECT COUNT(*) FROM roles`
	err := r.db.QueryRow(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "failed to count roles")
	}

	// Get roles
	query := `
		SELECT id, name, description, created_by, created_at, updated_by, updated_at
		FROM roles
		ORDER BY name
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "failed to list roles")
	}
	defer rows.Close()

	roles := make([]*Role, 0)
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedBy,
			&role.CreatedAt,
			&role.UpdatedBy,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "failed to scan role")
		}

		// Load permissions
		role.Permissions, _ = r.getRolePermissions(ctx, role.ID)

		roles = append(roles, role)
	}

	return roles, total, nil
}

// GetUserPermissions retrieves all permissions for a user
func (r *RoleRepository) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT DISTINCT p.code
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY p.code
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get user permissions")
	}
	defer rows.Close()

	permissions := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to scan permission")
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// CheckPermission checks if a user has a specific permission
func (r *RoleRepository) CheckPermission(ctx context.Context, userID, permission string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM permissions p
			INNER JOIN role_permissions rp ON p.id = rp.permission_id
			INNER JOIN user_roles ur ON rp.role_id = ur.role_id
			WHERE ur.user_id = $1 AND p.code = $2
		)
	`

	var hasPermission bool
	err := r.db.QueryRow(ctx, query, userID, permission).Scan(&hasPermission)
	if err != nil {
		return false, errors.Wrap(err, errors.ErrCodeInternal, "failed to check permission")
	}

	return hasPermission, nil
}

// getRolePermissions retrieves permission codes for a role
func (r *RoleRepository) getRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	query := `
		SELECT p.code
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.code
	`

	rows, err := r.db.Query(ctx, query, roleID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get role permissions")
	}
	defer rows.Close()

	permissions := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to scan permission")
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}
