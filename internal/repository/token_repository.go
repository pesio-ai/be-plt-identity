package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pesio-ai/be-go-common/database"
	"github.com/pesio-ai/be-go-common/errors"
)

// RefreshToken represents a refresh token entity
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

// TokenRepository handles token data operations
type TokenRepository struct {
	db *database.DB
}

// NewTokenRepository creates a new token repository
func NewTokenRepository(db *database.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// Create creates a new refresh token
func (r *TokenRepository) Create(ctx context.Context, token *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`

	err := r.db.QueryRow(ctx, query,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to create refresh token")
	}

	return nil
}

// GetByTokenHash retrieves a refresh token by token hash
func (r *TokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	token := &RefreshToken{}

	query := `
		SELECT id, user_id, token_hash, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.Revoked,
		&token.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, errors.NotFound("refresh_token", tokenHash)
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get refresh token")
	}

	return token, nil
}

// Revoke revokes a refresh token
func (r *TokenRepository) Revoke(ctx context.Context, tokenHash string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`

	_, err := r.db.Exec(ctx, query, tokenHash)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to revoke token")
	}

	return nil
}

// RevokeAllForUser revokes all refresh tokens for a user
func (r *TokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to revoke user tokens")
	}

	return nil
}

// DeleteExpired deletes expired tokens
func (r *TokenRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`

	_, err := r.db.Exec(ctx, query)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to delete expired tokens")
	}

	return nil
}

// LogAuthEvent logs an authentication event
func (r *TokenRepository) LogAuthEvent(ctx context.Context, userID, eventType, ipAddress, userAgent string, success bool, failureReason string) error {
	query := `
		INSERT INTO auth_audit_log (user_id, event_type, ip_address, user_agent, success, failure_reason)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}

	var failureReasonPtr *string
	if failureReason != "" {
		failureReasonPtr = &failureReason
	}

	_, err := r.db.Exec(ctx, query, userIDPtr, eventType, ipAddress, userAgent, success, failureReasonPtr)
	if err != nil {
		// Log but don't fail the operation
		return errors.Wrap(err, errors.ErrCodeInternal, "failed to log auth event")
	}

	return nil
}
