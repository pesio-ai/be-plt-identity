package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pesio-ai/be-go-common/logger"
)

type UserRepository struct {
	db  *pgxpool.Pool
	log *logger.Logger
}

func NewUserRepository(db *pgxpool.Pool, log *logger.Logger) *UserRepository {
	return &UserRepository{
		db:  db,
		log: log,
	}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *User) error {
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	query := `
		INSERT INTO users (
			id, entity_id, email, email_verified, password_hash,
			first_name, last_name, phone, profile_photo_url,
			timezone, locale, status, user_type,
			created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
	`

	_, err := r.db.Exec(ctx, query,
		user.ID, user.EntityID, user.Email, user.EmailVerified, user.PasswordHash,
		user.FirstName, user.LastName, user.Phone, user.ProfilePhotoURL,
		user.Timezone, user.Locale, user.Status, user.UserType,
		user.CreatedAt, user.UpdatedAt, user.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id, entityID string) (*User, error) {
	user := &User{}

	query := `
		SELECT id, entity_id, email, email_verified, password_hash,
			   first_name, last_name, phone, profile_photo_url,
			   timezone, locale, status, user_type,
			   last_login_at, failed_login_attempts, locked_until,
			   created_at, updated_at, created_by, updated_by
		FROM users
		WHERE id = $1 AND entity_id = $2
	`

	err := r.db.QueryRow(ctx, query, id, entityID).Scan(
		&user.ID, &user.EntityID, &user.Email, &user.EmailVerified, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Phone, &user.ProfilePhotoURL,
		&user.Timezone, &user.Locale, &user.Status, &user.UserType,
		&user.LastLoginAt, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.CreatedBy, &user.UpdatedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email and entity domain
func (r *UserRepository) GetByEmail(ctx context.Context, email, entityID string) (*User, error) {
	user := &User{}

	query := `
		SELECT id, entity_id, email, email_verified, password_hash,
			   first_name, last_name, phone, profile_photo_url,
			   timezone, locale, status, user_type,
			   last_login_at, failed_login_attempts, locked_until,
			   created_at, updated_at, created_by, updated_by
		FROM users
		WHERE email = $1 AND entity_id = $2
	`

	err := r.db.QueryRow(ctx, query, email, entityID).Scan(
		&user.ID, &user.EntityID, &user.Email, &user.EmailVerified, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Phone, &user.ProfilePhotoURL,
		&user.Timezone, &user.Locale, &user.Status, &user.UserType,
		&user.LastLoginAt, &user.FailedLoginAttempts, &user.LockedUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.CreatedBy, &user.UpdatedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

// Update updates user information
func (r *UserRepository) Update(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users SET
			first_name = $1, last_name = $2, phone = $3,
			profile_photo_url = $4, timezone = $5, locale = $6,
			status = $7, updated_at = $8, updated_by = $9
		WHERE id = $10 AND entity_id = $11
	`

	result, err := r.db.Exec(ctx, query,
		user.FirstName, user.LastName, user.Phone,
		user.ProfilePhotoURL, user.Timezone, user.Locale,
		user.Status, user.UpdatedAt, user.UpdatedBy,
		user.ID, user.EntityID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdatePassword updates the user's password hash
func (r *UserRepository) UpdatePassword(ctx context.Context, userID, entityID, passwordHash string) error {
	query := `
		UPDATE users SET
			password_hash = $1,
			updated_at = $2
		WHERE id = $3 AND entity_id = $4
	`

	result, err := r.db.Exec(ctx, query, passwordHash, time.Now(), userID, entityID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID, entityID string) error {
	now := time.Now()

	query := `
		UPDATE users SET
			last_login_at = $1,
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = $2
		WHERE id = $3 AND entity_id = $4
	`

	_, err := r.db.Exec(ctx, query, now, now, userID, entityID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// IncrementFailedLoginAttempts increments failed login counter
func (r *UserRepository) IncrementFailedLoginAttempts(ctx context.Context, userID, entityID string) error {
	query := `
		UPDATE users SET
			failed_login_attempts = failed_login_attempts + 1,
			updated_at = $1
		WHERE id = $2 AND entity_id = $3
	`

	_, err := r.db.Exec(ctx, query, time.Now(), userID, entityID)
	if err != nil {
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}

	return nil
}

// LockAccount locks a user account
func (r *UserRepository) LockAccount(ctx context.Context, userID, entityID string, duration time.Duration) error {
	lockUntil := time.Now().Add(duration)

	query := `
		UPDATE users SET
			locked_until = $1,
			updated_at = $2
		WHERE id = $3 AND entity_id = $4
	`

	_, err := r.db.Exec(ctx, query, lockUntil, time.Now(), userID, entityID)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

// Deactivate deactivates a user account
func (r *UserRepository) Deactivate(ctx context.Context, userID, entityID, deactivatedBy string) error {
	query := `
		UPDATE users SET
			status = 'deactivated',
			updated_at = $1,
			updated_by = $2
		WHERE id = $3 AND entity_id = $4
	`

	result, err := r.db.Exec(ctx, query, time.Now(), deactivatedBy, userID, entityID)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}
