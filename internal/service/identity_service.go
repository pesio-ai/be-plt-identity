package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pesio-ai/be-go-common/errors"
	"github.com/pesio-ai/be-go-common/logger"
	"github.com/pesio-ai/be-go-common/redis"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// JWT configuration
const (
	AccessTokenDuration  = 1 * time.Hour
	RefreshTokenDuration = 7 * 24 * time.Hour
	jwtSecret            = "CHANGE_ME_IN_PRODUCTION" // TODO: Load from environment
)

// IdentityService handles identity business logic
type IdentityService struct {
	userRepo  *repository.UserRepository
	roleRepo  *repository.RoleRepository
	tokenRepo *repository.TokenRepository
	redis     *redis.Client
	log       *logger.Logger
}

// NewIdentityService creates a new identity service
func NewIdentityService(
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	tokenRepo *repository.TokenRepository,
	redis *redis.Client,
	log *logger.Logger,
) *IdentityService {
	return &IdentityService{
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		tokenRepo: tokenRepo,
		redis:     redis,
		log:       log,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string
	Password string
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *repository.User
}

// Login authenticates a user and returns tokens
func (s *IdentityService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		s.tokenRepo.LogAuthEvent(ctx, "", "login", "", "", false, "user not found")
		return nil, errors.Unauthorized("invalid email or password")
	}

	// Check if user is active
	if user.Status != "active" {
		s.tokenRepo.LogAuthEvent(ctx, user.ID, "login", "", "", false, "user inactive")
		return nil, errors.Forbidden("user account is not active")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.tokenRepo.LogAuthEvent(ctx, user.ID, "login", "", "", false, "invalid password")
		return nil, errors.Unauthorized("invalid email or password")
	}

	// Get user permissions
	permissions, err := s.roleRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Generate access token
	accessToken, err := s.generateAccessToken(user.ID, permissions)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Update last login
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Log successful login
	s.tokenRepo.LogAuthEvent(ctx, user.ID, "login", "", "", true, "")

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         user,
	}, nil
}

// Logout logs out a user by revoking refresh tokens
func (s *IdentityService) Logout(ctx context.Context, userID string) error {
	// Revoke all refresh tokens for user
	if err := s.tokenRepo.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}

	// Log logout event
	s.tokenRepo.LogAuthEvent(ctx, userID, "logout", "", "", true, "")

	return nil
}

// RefreshToken generates new tokens from a refresh token
func (s *IdentityService) RefreshToken(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	// Hash the refresh token
	tokenHash := hashToken(refreshToken)

	// Get refresh token from database
	token, err := s.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, errors.Unauthorized("invalid refresh token")
	}

	// Check if token is revoked
	if token.Revoked {
		return nil, errors.Unauthorized("refresh token revoked")
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return nil, errors.Unauthorized("refresh token expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	// Check if user is active
	if user.Status != "active" {
		return nil, errors.Forbidden("user account is not active")
	}

	// Get user permissions
	permissions, err := s.roleRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(user.ID, permissions)
	if err != nil {
		return nil, err
	}

	// Generate new refresh token
	newRefreshToken, err := s.generateRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Revoke old refresh token
	s.tokenRepo.Revoke(ctx, tokenHash)

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		User:         user,
	}, nil
}

// ValidateToken validates an access token and returns user ID and permissions
func (s *IdentityService) ValidateToken(ctx context.Context, tokenString string) (string, []string, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return "", nil, errors.Unauthorized("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, errors.Unauthorized("invalid token claims")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return "", nil, errors.Unauthorized("invalid user ID in token")
	}

	// Extract permissions
	permsInterface, ok := claims["permissions"].([]interface{})
	if !ok {
		return userID, []string{}, nil
	}

	permissions := make([]string, len(permsInterface))
	for i, p := range permsInterface {
		permissions[i], _ = p.(string)
	}

	return userID, permissions, nil
}

// CreateUser creates a new user
func (s *IdentityService) CreateUser(ctx context.Context, email, password, firstName, lastName string, entityIDs, roleIDs []string, createdBy string) (*repository.User, error) {
	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.Internal("failed to hash password", err)
	}

	// Create user
	user := &repository.User{
		Email:        email,
		PasswordHash: string(passwordHash),
		FirstName:    firstName,
		LastName:     lastName,
		Status:       "active",
		CreatedBy:    &createdBy,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Assign entities
	for _, entityID := range entityIDs {
		s.userRepo.AssignEntity(ctx, user.ID, entityID, createdBy)
	}

	// Assign roles
	for _, roleID := range roleIDs {
		s.userRepo.AssignRole(ctx, user.ID, roleID, createdBy)
	}

	// Reload user with entities and roles
	return s.userRepo.GetByID(ctx, user.ID)
}

// GetUser retrieves a user by ID
func (s *IdentityService) GetUser(ctx context.Context, id string) (*repository.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

// UpdateUser updates a user
func (s *IdentityService) UpdateUser(ctx context.Context, id, email, firstName, lastName, status, updatedBy string) (*repository.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	user.Email = email
	user.FirstName = firstName
	user.LastName = lastName
	user.Status = status
	user.UpdatedBy = &updatedBy

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return s.userRepo.GetByID(ctx, id)
}

// DeleteUser deletes a user
func (s *IdentityService) DeleteUser(ctx context.Context, id string) error {
	return s.userRepo.Delete(ctx, id)
}

// ListUsers lists users with pagination
func (s *IdentityService) ListUsers(ctx context.Context, entityID, status string, page, pageSize int) ([]*repository.User, int64, error) {
	offset := (page - 1) * pageSize
	return s.userRepo.List(ctx, entityID, status, pageSize, offset)
}

// CheckPermission checks if a user has a permission
func (s *IdentityService) CheckPermission(ctx context.Context, userID, permission string) (bool, error) {
	return s.roleRepo.CheckPermission(ctx, userID, permission)
}

// generateAccessToken generates a JWT access token
func (s *IdentityService) generateAccessToken(userID string, permissions []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":         userID,
		"permissions": permissions,
		"exp":         time.Now().Add(AccessTokenDuration).Unix(),
		"iat":         time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// generateRefreshToken generates a refresh token
func (s *IdentityService) generateRefreshToken(ctx context.Context, userID string) (string, error) {
	// Generate random token
	tokenString := uuid.New().String()

	// Hash token for storage
	tokenHash := hashToken(tokenString)

	// Store refresh token
	refreshToken := &repository.RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(RefreshTokenDuration),
	}

	if err := s.tokenRepo.Create(ctx, refreshToken); err != nil {
		return "", err
	}

	return tokenString, nil
}

// hashToken hashes a token using SHA256
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
