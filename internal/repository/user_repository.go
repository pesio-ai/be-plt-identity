package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/pesio-ai/be-go-common/database"
	"github.com/pesio-ai/be-go-common/errors"
)

// User represents a user entity
type User struct {
	ID           string
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	Status       string
	LastLoginAt  *string
	EntityIDs    []string
	RoleIDs      []string
	CreatedBy    *string
	CreatedAt    string
	UpdatedBy    *string
	UpdatedAt    string
}

// UserRepository handles user data operations
type UserRepository struct {
	db *database.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *database.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (email, password_hash, first_name, last_name, status, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.Status,
		user.CreatedBy,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to create user")
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	user := &User{}

	query := `
		SELECT id, email, password_hash, first_name, last_name, status,
		       last_login_at, created_by, created_at, updated_by, updated_at
		FROM users
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.Status,
		&user.LastLoginAt,
		&user.CreatedBy,
		&user.CreatedAt,
		&user.UpdatedBy,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, errors.NotFound("user", id)
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get user")
	}

	// Load entity IDs
	user.EntityIDs, err = r.getUserEntities(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load role IDs
	user.RoleIDs, err = r.getUserRoles(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}

	query := `
		SELECT id, email, password_hash, first_name, last_name, status,
		       last_login_at, created_by, created_at, updated_by, updated_at
		FROM users
		WHERE email = $1
	`

	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.Status,
		&user.LastLoginAt,
		&user.CreatedBy,
		&user.CreatedAt,
		&user.UpdatedBy,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, errors.NotFound("user", email)
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get user by email")
	}

	// Load entity IDs
	user.EntityIDs, err = r.getUserEntities(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Load role IDs
	user.RoleIDs, err = r.getUserRoles(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *User) error {
	query := `
		UPDATE users
		SET email = $2, first_name = $3, last_name = $4, status = $5, updated_by = $6, updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.db.QueryRow(ctx, query,
		user.ID,
		user.Email,
		user.FirstName,
		user.LastName,
		user.Status,
		user.UpdatedBy,
	).Scan(&user.UpdatedAt)

	if err == pgx.ErrNoRows {
		return errors.NotFound("user", user.ID)
	}
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to update user")
	}

	return nil
}

// Delete deletes a user
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`

	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to delete user")
	}

	if tag.RowsAffected() == 0 {
		return errors.NotFound("user", id)
	}

	return nil
}

// List retrieves users with pagination
func (r *UserRepository) List(ctx context.Context, entityID string, status string, limit, offset int) ([]*User, int64, error) {
	// Build query
	query := `
		SELECT DISTINCT u.id, u.email, u.first_name, u.last_name, u.status,
		       u.last_login_at, u.created_by, u.created_at, u.updated_by, u.updated_at
		FROM users u
	`

	countQuery := `SELECT COUNT(DISTINCT u.id) FROM users u`

	args := []interface{}{}
	argCount := 1

	if entityID != "" {
		query += ` INNER JOIN user_entities ue ON u.id = ue.user_id`
		countQuery += ` INNER JOIN user_entities ue ON u.id = ue.user_id`
		query += fmt.Sprintf(` WHERE ue.entity_id = $%d`, argCount)
		countQuery += fmt.Sprintf(` WHERE ue.entity_id = $%d`, argCount)
		args = append(args, entityID)
		argCount++

		if status != "" {
			query += fmt.Sprintf(` AND u.status = $%d`, argCount)
			countQuery += fmt.Sprintf(` AND u.status = $%d`, argCount)
			args = append(args, status)
			argCount++
		}
	} else if status != "" {
		query += fmt.Sprintf(` WHERE u.status = $%d`, argCount)
		countQuery += fmt.Sprintf(` WHERE u.status = $%d`, argCount)
		args = append(args, status)
		argCount++
	}

	query += ` ORDER BY u.created_at DESC`
	query += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, argCount, argCount+1)
	args = append(args, limit, offset)

	// Get total count
	var total int64
	err := r.db.QueryRow(ctx, countQuery, args[:argCount-1]...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "failed to count users")
	}

	// Get users
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "failed to list users")
	}
	defer rows.Close()

	users := make([]*User, 0)
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.Status,
			&user.LastLoginAt,
			&user.CreatedBy,
			&user.CreatedAt,
			&user.UpdatedBy,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "failed to scan user")
		}

		// Load entity IDs
		user.EntityIDs, _ = r.getUserEntities(ctx, user.ID)
		// Load role IDs
		user.RoleIDs, _ = r.getUserRoles(ctx, user.ID)

		users = append(users, user)
	}

	return users, total, nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserRepository) UpdateLastLogin(ctx context.Context, id string) error {
	query := `UPDATE users SET last_login_at = NOW() WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to update last login")
	}

	return nil
}

// AssignRole assigns a role to a user
func (r *UserRepository) AssignRole(ctx context.Context, userID, roleID, createdBy string) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, created_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`

	_, err := r.db.Exec(ctx, query, userID, roleID, createdBy)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to assign role")
	}

	return nil
}

// RevokeRole revokes a role from a user
func (r *UserRepository) RevokeRole(ctx context.Context, userID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`

	_, err := r.db.Exec(ctx, query, userID, roleID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to revoke role")
	}

	return nil
}

// AssignEntity assigns an entity to a user
func (r *UserRepository) AssignEntity(ctx context.Context, userID, entityID, createdBy string) error {
	query := `
		INSERT INTO user_entities (user_id, entity_id, created_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, entity_id) DO NOTHING
	`

	_, err := r.db.Exec(ctx, query, userID, entityID, createdBy)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to assign entity")
	}

	return nil
}

// getUserEntities retrieves entity IDs for a user
func (r *UserRepository) getUserEntities(ctx context.Context, userID string) ([]string, error) {
	query := `SELECT entity_id FROM user_entities WHERE user_id = $1`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get user entities")
	}
	defer rows.Close()

	entityIDs := make([]string, 0)
	for rows.Next() {
		var entityID string
		if err := rows.Scan(&entityID); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to scan entity ID")
		}
		entityIDs = append(entityIDs, entityID)
	}

	return entityIDs, nil
}

// getUserRoles retrieves role IDs for a user
func (r *UserRepository) getUserRoles(ctx context.Context, userID string) ([]string, error) {
	query := `SELECT role_id FROM user_roles WHERE user_id = $1`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get user roles")
	}
	defer rows.Close()

	roleIDs := make([]string, 0)
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to scan role ID")
		}
		roleIDs = append(roleIDs, roleID)
	}

	return roleIDs, nil
}
