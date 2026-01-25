package handler

import (
	"context"

	"github.com/pesio-ai/be-go-common/logger"
	commonpb "github.com/pesio-ai/be-go-proto/gen/go/common"
	pb "github.com/pesio-ai/be-go-proto/gen/go/platform"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	"github.com/pesio-ai/be-identity-service/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GRPCHandler struct {
	pb.UnimplementedIdentityServiceServer
	authService *service.AuthService
	userService *service.UserService
	roleService *service.RoleService
	log         *logger.Logger
}

func NewGRPCHandler(
	authService *service.AuthService,
	userService *service.UserService,
	roleService *service.RoleService,
	log *logger.Logger,
) *GRPCHandler {
	return &GRPCHandler{
		authService: authService,
		userService: userService,
		roleService: roleService,
		log:         log,
	}
}

// Login authenticates a user
func (h *GRPCHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	h.log.Info().
		Str("email", req.Email).
		Str("entity_domain", req.EntityDomain).
		Msg("gRPC Login request")

	loginReq := &service.LoginRequest{
		Email:        req.Email,
		Password:     req.Password,
		EntityDomain: req.EntityDomain,
		DeviceType:   req.DeviceType,
		DeviceName:   req.DeviceName,
		IPAddress:    req.IpAddress,
	}

	resp, err := h.authService.Login(ctx, loginReq)
	if err != nil {
		h.log.Error().Err(err).Msg("Login failed")
		return nil, toGRPCError(err)
	}

	return &pb.LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		User:         userToProto(resp.User),
		Session:      sessionToProto(resp.Session),
	}, nil
}

// RefreshToken generates new tokens
func (h *GRPCHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.LoginResponse, error) {
	h.log.Info().Msg("gRPC RefreshToken request")

	tokenPair, err := h.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		h.log.Error().Err(err).Msg("RefreshToken failed")
		return nil, toGRPCError(err)
	}

	return &pb.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
	}, nil
}

// Logout deactivates a session
func (h *GRPCHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*commonpb.Response, error) {
	h.log.Info().Str("session_id", req.SessionId).Msg("gRPC Logout request")

	err := h.authService.Logout(ctx, req.SessionId)
	if err != nil {
		h.log.Error().Err(err).Msg("Logout failed")
		return nil, toGRPCError(err)
	}

	return &commonpb.Response{
		Success: true,
		Message: "Logged out successfully",
	}, nil
}

// ValidateToken validates a JWT token
func (h *GRPCHandler) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	claims, err := h.authService.ValidateToken(ctx, req.Token)
	if err != nil {
		return &pb.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:     true,
		UserId:    claims.UserID,
		EntityId:  claims.EntityID,
		SessionId: claims.SessionID,
		ExpiresAt: timestamppb.New(claims.ExpiresAt.Time),
	}, nil
}

// CreateUser creates a new user
func (h *GRPCHandler) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	h.log.Info().
		Str("email", req.Email).
		Str("entity_id", req.EntityId).
		Msg("gRPC CreateUser request")

	createReq := &service.CreateUserRequest{
		EntityID:  req.EntityId,
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Phone:     stringPtr(req.Phone),
		Timezone:  req.Timezone,
		Locale:    req.Locale,
		UserType:  req.UserType,
		CreatedBy: req.CreatedBy,
	}

	user, err := h.userService.CreateUser(ctx, createReq)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateUser failed")
		return nil, toGRPCError(err)
	}

	return userToProto(user), nil
}

// GetUser retrieves a user
func (h *GRPCHandler) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	h.log.Info().
		Str("id", req.Id).
		Str("entity_id", req.EntityId).
		Msg("gRPC GetUser request")

	user, err := h.userService.GetUser(ctx, req.Id, req.EntityId)
	if err != nil {
		h.log.Error().Err(err).Msg("GetUser failed")
		return nil, toGRPCError(err)
	}

	return userToProto(user), nil
}

// UpdateUser updates a user
func (h *GRPCHandler) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.User, error) {
	h.log.Info().
		Str("id", req.Id).
		Str("entity_id", req.EntityId).
		Msg("gRPC UpdateUser request")

	updateReq := &service.UpdateUserRequest{
		ID:        req.Id,
		EntityID:  req.EntityId,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Phone:     stringPtr(req.Phone),
		Timezone:  req.Timezone,
		Locale:    req.Locale,
		Status:    req.Status,
		UpdatedBy: req.UpdatedBy,
	}

	user, err := h.userService.UpdateUser(ctx, updateReq)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateUser failed")
		return nil, toGRPCError(err)
	}

	return userToProto(user), nil
}

// DeactivateUser deactivates a user
func (h *GRPCHandler) DeactivateUser(ctx context.Context, req *pb.DeactivateUserRequest) (*commonpb.Response, error) {
	h.log.Info().
		Str("id", req.Id).
		Str("entity_id", req.EntityId).
		Msg("gRPC DeactivateUser request")

	err := h.userService.DeactivateUser(ctx, req.Id, req.EntityId, req.DeactivatedBy)
	if err != nil {
		h.log.Error().Err(err).Msg("DeactivateUser failed")
		return nil, toGRPCError(err)
	}

	return &commonpb.Response{
		Success: true,
		Message: "User deactivated successfully",
	}, nil
}

// ChangePassword changes a user's password
func (h *GRPCHandler) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*commonpb.Response, error) {
	h.log.Info().Str("user_id", req.UserId).Msg("gRPC ChangePassword request")

	// Extract entity_id from context (would be set by auth middleware)
	// For now, we'll need to get it from the user record
	// This is a simplification - in production, entity_id should come from the validated token

	err := h.authService.ChangePassword(ctx, req.UserId, "", req.CurrentPassword, req.NewPassword)
	if err != nil {
		h.log.Error().Err(err).Msg("ChangePassword failed")
		return nil, toGRPCError(err)
	}

	return &commonpb.Response{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}

// CreateRole creates a new role
func (h *GRPCHandler) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.Role, error) {
	h.log.Info().Str("name", req.Name).Msg("gRPC CreateRole request")

	createReq := &service.CreateRoleRequest{
		EntityID:    stringPtr(req.EntityId),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: stringPtr(req.Description),
		CreatedBy:   req.CreatedBy,
	}

	role, err := h.roleService.CreateRole(ctx, createReq)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateRole failed")
		return nil, toGRPCError(err)
	}

	return roleToProto(role), nil
}

// GetRole retrieves a role
func (h *GRPCHandler) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	h.log.Info().Str("id", req.Id).Msg("gRPC GetRole request")

	role, err := h.roleService.GetRole(ctx, req.Id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetRole failed")
		return nil, toGRPCError(err)
	}

	return roleToProto(role), nil
}

// ListRoles lists roles
func (h *GRPCHandler) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	h.log.Info().Str("entity_id", req.EntityId).Msg("gRPC ListRoles request")

	roles, err := h.roleService.ListRoles(ctx, stringPtr(req.EntityId), req.ActiveOnly)
	if err != nil {
		h.log.Error().Err(err).Msg("ListRoles failed")
		return nil, toGRPCError(err)
	}

	pbRoles := make([]*pb.Role, len(roles))
	for i, role := range roles {
		pbRoles[i] = roleToProto(role)
	}

	return &pb.ListRolesResponse{
		Roles: pbRoles,
	}, nil
}

// AssignRole assigns a role to a user
func (h *GRPCHandler) AssignRole(ctx context.Context, req *pb.AssignRoleRequest) (*commonpb.Response, error) {
	h.log.Info().
		Str("user_id", req.UserId).
		Str("role_id", req.RoleId).
		Msg("gRPC AssignRole request")

	err := h.roleService.AssignRole(ctx, req.UserId, req.RoleId, req.EntityId, req.AssignedBy)
	if err != nil {
		h.log.Error().Err(err).Msg("AssignRole failed")
		return nil, toGRPCError(err)
	}

	return &commonpb.Response{
		Success: true,
		Message: "Role assigned successfully",
	}, nil
}

// UnassignRole removes a role from a user
func (h *GRPCHandler) UnassignRole(ctx context.Context, req *pb.UnassignRoleRequest) (*commonpb.Response, error) {
	h.log.Info().
		Str("user_id", req.UserId).
		Str("role_id", req.RoleId).
		Msg("gRPC UnassignRole request")

	err := h.roleService.UnassignRole(ctx, req.UserId, req.RoleId, req.EntityId)
	if err != nil {
		h.log.Error().Err(err).Msg("UnassignRole failed")
		return nil, toGRPCError(err)
	}

	return &commonpb.Response{
		Success: true,
		Message: "Role unassigned successfully",
	}, nil
}

// GetUserPermissions retrieves user permissions
func (h *GRPCHandler) GetUserPermissions(ctx context.Context, req *pb.GetUserPermissionsRequest) (*pb.GetUserPermissionsResponse, error) {
	h.log.Info().
		Str("user_id", req.UserId).
		Str("entity_id", req.EntityId).
		Msg("gRPC GetUserPermissions request")

	permissions, err := h.userService.GetUserPermissions(ctx, req.UserId, req.EntityId)
	if err != nil {
		h.log.Error().Err(err).Msg("GetUserPermissions failed")
		return nil, toGRPCError(err)
	}

	pbPermissions := make([]*pb.Permission, len(permissions))
	for i, perm := range permissions {
		pbPermissions[i] = permissionToProto(perm)
	}

	return &pb.GetUserPermissionsResponse{
		Permissions: pbPermissions,
	}, nil
}

// CheckPermission checks if a user has a permission
func (h *GRPCHandler) CheckPermission(ctx context.Context, req *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	h.log.Info().
		Str("user_id", req.UserId).
		Str("permission", req.Module+":"+req.Resource+":"+req.Action).
		Msg("gRPC CheckPermission request")

	allowed, reason, err := h.userService.CheckUserPermission(
		ctx, req.UserId, req.EntityId, req.Module, req.Resource, req.Action,
	)
	if err != nil {
		h.log.Error().Err(err).Msg("CheckPermission failed")
		return nil, toGRPCError(err)
	}

	return &pb.CheckPermissionResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

// Helper functions

func userToProto(user *repository.User) *pb.User {
	pbUser := &pb.User{
		Id:            user.ID,
		EntityId:      user.EntityID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Phone:         stringToProto(user.Phone),
		ProfilePhotoUrl: stringToProto(user.ProfilePhotoURL),
		Timezone:      user.Timezone,
		Locale:        user.Locale,
		Status:        user.Status,
		UserType:      user.UserType,
		CreatedAt:     timestamppb.New(user.CreatedAt),
		UpdatedAt:     timestamppb.New(user.UpdatedAt),
	}

	if user.LastLoginAt != nil {
		pbUser.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	return pbUser
}

func roleToProto(role *repository.Role) *pb.Role {
	return &pb.Role{
		Id:          role.ID,
		EntityId:    stringToProto(role.EntityID),
		Name:        role.Name,
		DisplayName: role.DisplayName,
		Description: stringToProto(role.Description),
		RoleType:    role.RoleType,
		IsActive:    role.IsActive,
		CreatedAt:   timestamppb.New(role.CreatedAt),
		UpdatedAt:   timestamppb.New(role.UpdatedAt),
	}
}

func permissionToProto(perm *repository.Permission) *pb.Permission {
	return &pb.Permission{
		Id:          perm.ID,
		Module:      perm.Module,
		Resource:    perm.Resource,
		Action:      perm.Action,
		Name:        perm.Name,
		Description: stringToProto(perm.Description),
		IsSensitive: perm.IsSensitive,
	}
}

func sessionToProto(session *repository.Session) *pb.Session {
	pbSession := &pb.Session{
		Id:             session.ID,
		UserId:         session.UserID,
		EntityId:       session.EntityID,
		DeviceType:     stringToProto(session.DeviceType),
		DeviceName:     stringToProto(session.DeviceName),
		IpAddress:      stringToProto(session.IPAddress),
		CreatedAt:      timestamppb.New(session.CreatedAt),
		ExpiresAt:      timestamppb.New(session.ExpiresAt),
		LastActivityAt: timestamppb.New(session.LastActivityAt),
		IsActive:       session.IsActive,
	}

	return pbSession
}

func stringToProto(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toGRPCError(err error) error {
	// Map service errors to gRPC status codes
	switch err {
	case service.ErrInvalidCredentials:
		return status.Error(codes.Unauthenticated, err.Error())
	case service.ErrAccountLocked:
		return status.Error(codes.PermissionDenied, err.Error())
	case service.ErrAccountInactive:
		return status.Error(codes.PermissionDenied, err.Error())
	case service.ErrSessionNotFound:
		return status.Error(codes.NotFound, err.Error())
	case service.ErrInvalidToken:
		return status.Error(codes.Unauthenticated, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
