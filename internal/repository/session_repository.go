package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pesio-ai/be-go-common/logger"
)

type SessionRepository struct {
	db  *pgxpool.Pool
	log *logger.Logger
}

func NewSessionRepository(db *pgxpool.Pool, log *logger.Logger) *SessionRepository {
	return &SessionRepository{
		db:  db,
		log: log,
	}
}

// Create creates a new session
func (r *SessionRepository) Create(ctx context.Context, session *Session, refreshToken string) error {
	session.ID = uuid.New().String()
	session.CreatedAt = time.Now()
	session.LastActivityAt = time.Now()

	// Hash the refresh token before storing
	hash := sha256.Sum256([]byte(refreshToken))
	refreshTokenHash := hex.EncodeToString(hash[:])
	session.RefreshTokenHash = &refreshTokenHash

	query := `
		INSERT INTO sessions (
			id, user_id, entity_id, device_type, device_name, ip_address, user_agent,
			created_at, expires_at, last_activity_at, is_active,
			refresh_token_hash, refresh_token_expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`

	_, err := r.db.Exec(ctx, query,
		session.ID, session.UserID, session.EntityID, session.DeviceType, session.DeviceName,
		session.IPAddress, session.UserAgent, session.CreatedAt, session.ExpiresAt,
		session.LastActivityAt, session.IsActive, session.RefreshTokenHash,
		session.RefreshTokenExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetByID retrieves a session by ID
func (r *SessionRepository) GetByID(ctx context.Context, sessionID string) (*Session, error) {
	session := &Session{}

	query := `
		SELECT id, user_id, entity_id, device_type, device_name, ip_address, user_agent,
			   created_at, expires_at, last_activity_at, is_active,
			   refresh_token_hash, refresh_token_expires_at
		FROM sessions
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, sessionID).Scan(
		&session.ID, &session.UserID, &session.EntityID, &session.DeviceType,
		&session.DeviceName, &session.IPAddress, &session.UserAgent,
		&session.CreatedAt, &session.ExpiresAt, &session.LastActivityAt,
		&session.IsActive, &session.RefreshTokenHash, &session.RefreshTokenExpiresAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

// UpdateLastActivity updates the last activity timestamp
func (r *SessionRepository) UpdateLastActivity(ctx context.Context, sessionID string) error {
	query := `
		UPDATE sessions
		SET last_activity_at = $1
		WHERE id = $2
	`

	_, err := r.db.Exec(ctx, query, time.Now(), sessionID)
	if err != nil {
		return fmt.Errorf("failed to update last activity: %w", err)
	}

	return nil
}

// Deactivate deactivates a session
func (r *SessionRepository) Deactivate(ctx context.Context, sessionID string) error {
	query := `
		UPDATE sessions
		SET is_active = false
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to deactivate session: %w", err)
	}

	return nil
}

// DeactivateUserSessions deactivates all sessions for a user
func (r *SessionRepository) DeactivateUserSessions(ctx context.Context, userID, entityID string) error {
	query := `
		UPDATE sessions
		SET is_active = false
		WHERE user_id = $1 AND entity_id = $2 AND is_active = true
	`

	_, err := r.db.Exec(ctx, query, userID, entityID)
	if err != nil {
		return fmt.Errorf("failed to deactivate user sessions: %w", err)
	}

	return nil
}

// DeleteExpired deletes expired sessions
func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	query := `
		DELETE FROM sessions
		WHERE expires_at < $1
	`

	_, err := r.db.Exec(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return nil
}

// ValidateRefreshToken checks if a refresh token is valid for a session
func (r *SessionRepository) ValidateRefreshToken(ctx context.Context, sessionID, refreshToken string) (bool, error) {
	// Hash the provided refresh token
	hash := sha256.Sum256([]byte(refreshToken))
	refreshTokenHash := hex.EncodeToString(hash[:])

	var storedHash *string
	var expiresAt *time.Time
	var isActive bool

	query := `
		SELECT refresh_token_hash, refresh_token_expires_at, is_active
		FROM sessions
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, sessionID).Scan(&storedHash, &expiresAt, &isActive)
	if err != nil {
		return false, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	// Check if session is active
	if !isActive {
		return false, nil
	}

	// Check if refresh token expired
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return false, nil
	}

	// Compare hashes
	if storedHash == nil || *storedHash != refreshTokenHash {
		return false, nil
	}

	return true, nil
}
