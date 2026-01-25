package service

import (
	"context"
	"fmt"

	"github.com/pesio-ai/be-go-common/logger"
	"github.com/pesio-ai/be-identity-service/internal/repository"
)

type RoleService struct {
	roleRepo *repository.RoleRepository
	log      *logger.Logger
}

func NewRoleService(roleRepo *repository.RoleRepository, log *logger.Logger) *RoleService {
	return &RoleService{
		roleRepo: roleRepo,
		log:      log,
	}
}

type CreateRoleRequest struct {
	EntityID    *string
	Name        string
	DisplayName string
	Description *string
	CreatedBy   string
}

// CreateRole creates a new role
func (s *RoleService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*repository.Role, error) {
	s.log.Info().
		Str("name", req.Name).
		Msg("Creating role")

	role := &repository.Role{
		EntityID:    req.EntityID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		RoleType:    "custom",
		IsActive:    true,
		CreatedBy:   &req.CreatedBy,
	}

	err := s.roleRepo.Create(ctx, role)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to create role")
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	s.log.Info().Str("role_id", role.ID).Msg("Role created successfully")
	return role, nil
}

// GetRole retrieves a role by ID
func (s *RoleService) GetRole(ctx context.Context, roleID string) (*repository.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}

// ListRoles retrieves all roles for an entity
func (s *RoleService) ListRoles(ctx context.Context, entityID *string, activeOnly bool) ([]*repository.Role, error) {
	roles, err := s.roleRepo.List(ctx, entityID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	return roles, nil
}

// AssignRole assigns a role to a user
func (s *RoleService) AssignRole(ctx context.Context, userID, roleID, entityID, assignedBy string) error {
	s.log.Info().
		Str("user_id", userID).
		Str("role_id", roleID).
		Str("entity_id", entityID).
		Msg("Assigning role to user")

	err := s.roleRepo.AssignToUser(ctx, userID, roleID, entityID, assignedBy)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to assign role")
		return fmt.Errorf("failed to assign role: %w", err)
	}

	s.log.Info().
		Str("user_id", userID).
		Str("role_id", roleID).
		Msg("Role assigned successfully")
	return nil
}

// UnassignRole removes a role from a user
func (s *RoleService) UnassignRole(ctx context.Context, userID, roleID, entityID string) error {
	s.log.Info().
		Str("user_id", userID).
		Str("role_id", roleID).
		Str("entity_id", entityID).
		Msg("Unassigning role from user")

	err := s.roleRepo.UnassignFromUser(ctx, userID, roleID, entityID)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to unassign role")
		return fmt.Errorf("failed to unassign role: %w", err)
	}

	s.log.Info().
		Str("user_id", userID).
		Str("role_id", roleID).
		Msg("Role unassigned successfully")
	return nil
}
