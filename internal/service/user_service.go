package service

import (
	"context"
	"fmt"

	"github.com/pesio-ai/be-lib-common/logger"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	"github.com/pesio-ai/be-identity-service/pkg/password"
)

type UserService struct {
	userRepo *repository.UserRepository
	roleRepo *repository.RoleRepository
	log      *logger.Logger
}

func NewUserService(
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	log *logger.Logger,
) *UserService {
	return &UserService{
		userRepo: userRepo,
		roleRepo: roleRepo,
		log:      log,
	}
}

type CreateUserRequest struct {
	EntityID  string
	Email     string
	Password  string
	FirstName string
	LastName  string
	Phone     *string
	Timezone  string
	Locale    string
	UserType  string
	CreatedBy string
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) (*repository.User, error) {
	s.log.Info().
		Str("email", req.Email).
		Str("entity_id", req.EntityID).
		Msg("Creating user")

	// Hash password
	passwordHash, err := password.Hash(req.Password, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &repository.User{
		EntityID:      req.EntityID,
		Email:         req.Email,
		EmailVerified: false,
		PasswordHash:  &passwordHash,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Phone:         req.Phone,
		Timezone:      req.Timezone,
		Locale:        req.Locale,
		Status:        "active",
		UserType:      req.UserType,
		CreatedBy:     &req.CreatedBy,
	}

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.log.Info().Str("user_id", user.ID).Msg("User created successfully")
	return user, nil
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, userID, entityID string) (*repository.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

type UpdateUserRequest struct {
	ID              string
	EntityID        string
	FirstName       string
	LastName        string
	Phone           *string
	Timezone        string
	Locale          string
	Status          string
	UpdatedBy       string
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*repository.User, error) {
	s.log.Info().
		Str("user_id", req.ID).
		Str("entity_id", req.EntityID).
		Msg("Updating user")

	// Get existing user
	user, err := s.userRepo.GetByID(ctx, req.ID, req.EntityID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Update fields
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Phone = req.Phone
	user.Timezone = req.Timezone
	user.Locale = req.Locale
	user.Status = req.Status
	user.UpdatedBy = &req.UpdatedBy

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to update user")
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.log.Info().Str("user_id", user.ID).Msg("User updated successfully")
	return user, nil
}

// DeactivateUser deactivates a user account
func (s *UserService) DeactivateUser(ctx context.Context, userID, entityID, deactivatedBy string) error {
	s.log.Info().
		Str("user_id", userID).
		Str("deactivated_by", deactivatedBy).
		Msg("Deactivating user")

	err := s.userRepo.Deactivate(ctx, userID, entityID, deactivatedBy)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to deactivate user")
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	s.log.Info().Str("user_id", userID).Msg("User deactivated successfully")
	return nil
}

// GetUserPermissions retrieves all permissions for a user
func (s *UserService) GetUserPermissions(ctx context.Context, userID, entityID string) ([]*repository.Permission, error) {
	permissions, err := s.roleRepo.GetUserPermissions(ctx, userID, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return permissions, nil
}

// CheckUserPermission checks if a user has a specific permission
func (s *UserService) CheckUserPermission(ctx context.Context, userID, entityID, module, resource, action string) (bool, string, error) {
	hasPermission, err := s.roleRepo.CheckUserPermission(ctx, userID, entityID, module, resource, action)
	if err != nil {
		return false, "", fmt.Errorf("failed to check permission: %w", err)
	}

	var reason string
	if hasPermission {
		reason = fmt.Sprintf("User has permission %s:%s:%s", module, resource, action)
	} else {
		reason = fmt.Sprintf("User does not have permission %s:%s:%s", module, resource, action)
	}

	return hasPermission, reason, nil
}
