package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pesio-ai/be-lib-common/logger"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	jwtpkg "github.com/pesio-ai/be-identity-service/pkg/jwt"
	"github.com/pesio-ai/be-identity-service/pkg/password"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAccountInactive    = errors.New("account is inactive")
	ErrSessionNotFound    = errors.New("session not found")
	ErrInvalidToken       = errors.New("invalid token")
)

const (
	MaxFailedLoginAttempts = 5
	AccountLockDuration    = 30 * time.Minute
)

type AuthService struct {
	userRepo    *repository.UserRepository
	roleRepo    *repository.RoleRepository
	sessionRepo *repository.SessionRepository
	jwtManager  *jwtpkg.Manager
	log         *logger.Logger
}

func NewAuthService(
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	sessionRepo *repository.SessionRepository,
	jwtManager *jwtpkg.Manager,
	log *logger.Logger,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		sessionRepo: sessionRepo,
		jwtManager:  jwtManager,
		log:         log,
	}
}

type LoginRequest struct {
	Email        string
	Password     string
	EntityDomain string
	DeviceType   string
	DeviceName   string
	IPAddress    string
}

type LoginResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *repository.User
	Session      *repository.Session
}

// Login authenticates a user and creates a session
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	s.log.Info().
		Str("email", req.Email).
		Str("entity_domain", req.EntityDomain).
		Str("device_type", req.DeviceType).
		Msg("Login attempt")

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email, req.EntityDomain)
	if err != nil {
		s.log.Warn().Err(err).Msg("User not found")
		return nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		s.log.Warn().Str("user_id", user.ID).Msg("Account is locked")
		return nil, ErrAccountLocked
	}

	// Check if account is active
	if user.Status != "active" {
		s.log.Warn().Str("user_id", user.ID).Str("status", user.Status).Msg("Account is inactive")
		return nil, ErrAccountInactive
	}

	// Verify password
	if user.PasswordHash == nil {
		s.log.Warn().Str("user_id", user.ID).Msg("User has no password (SSO-only)")
		return nil, ErrInvalidCredentials
	}

	valid, err := password.Verify(req.Password, *user.PasswordHash)
	if err != nil {
		s.log.Error().Err(err).Msg("Password verification failed")
		return nil, fmt.Errorf("password verification error: %w", err)
	}

	if !valid {
		// Increment failed login attempts
		_ = s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID, user.EntityID)

		// Lock account if too many failed attempts
		if user.FailedLoginAttempts+1 >= MaxFailedLoginAttempts {
			_ = s.userRepo.LockAccount(ctx, user.ID, user.EntityID, AccountLockDuration)
			s.log.Warn().Str("user_id", user.ID).Msg("Account locked due to too many failed login attempts")
			return nil, ErrAccountLocked
		}

		s.log.Warn().Str("user_id", user.ID).Msg("Invalid password")
		return nil, ErrInvalidCredentials
	}

	// Create session
	session := &repository.Session{
		UserID:     user.ID,
		EntityID:   user.EntityID,
		DeviceType: &req.DeviceType,
		DeviceName: &req.DeviceName,
		IPAddress:  &req.IPAddress,
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour), // 7 days
		IsActive:   true,
	}

	refreshTokenExpiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days
	session.RefreshTokenExpiresAt = &refreshTokenExpiresAt

	// Generate tokens
	tokenPair, err := s.jwtManager.GenerateTokenPair(user.ID, user.EntityID, "", user.Email)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to generate tokens")
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	// Create session in database with refresh token
	err = s.sessionRepo.Create(ctx, session, tokenPair.RefreshToken)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to create session")
		return nil, fmt.Errorf("session creation failed: %w", err)
	}

	// Regenerate tokens with session ID
	tokenPair, err = s.jwtManager.GenerateTokenPair(user.ID, user.EntityID, session.ID, user.Email)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to regenerate tokens with session ID")
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	// Update last login
	_ = s.userRepo.UpdateLastLogin(ctx, user.ID, user.EntityID)

	s.log.Info().
		Str("user_id", user.ID).
		Str("session_id", session.ID).
		Msg("Login successful")

	return &LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		User:         user,
		Session:      session,
	}, nil
}

// ValidateToken validates a JWT token
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*jwtpkg.Claims, error) {
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	// Verify session is still active
	if claims.SessionID != "" {
		session, err := s.sessionRepo.GetByID(ctx, claims.SessionID)
		if err != nil {
			return nil, ErrSessionNotFound
		}

		if !session.IsActive {
			return nil, ErrSessionNotFound
		}

		// Update last activity
		_ = s.sessionRepo.UpdateLastActivity(ctx, claims.SessionID)
	}

	return claims, nil
}

// RefreshToken generates a new access token using a refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*jwtpkg.TokenPair, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, ErrInvalidToken
	}

	// Validate refresh token against session
	valid, err := s.sessionRepo.ValidateRefreshToken(ctx, claims.SessionID, refreshToken)
	if err != nil || !valid {
		return nil, ErrInvalidToken
	}

	// Generate new token pair
	tokenPair, err := s.jwtManager.GenerateTokenPair(
		claims.UserID,
		claims.EntityID,
		claims.SessionID,
		claims.Email,
	)
	if err != nil {
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	return tokenPair, nil
}

// Logout deactivates a session
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	err := s.sessionRepo.Deactivate(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	s.log.Info().Str("session_id", sessionID).Msg("Logout successful")
	return nil
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(ctx context.Context, userID, entityID, currentPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID, entityID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify current password
	if user.PasswordHash != nil {
		valid, err := password.Verify(currentPassword, *user.PasswordHash)
		if err != nil || !valid {
			return ErrInvalidCredentials
		}
	}

	// Hash new password
	newHash, err := password.Hash(newPassword, nil)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	err = s.userRepo.UpdatePassword(ctx, userID, entityID, newHash)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Deactivate all sessions to force re-login
	_ = s.sessionRepo.DeactivateUserSessions(ctx, userID, entityID)

	s.log.Info().Str("user_id", userID).Msg("Password changed successfully")
	return nil
}
