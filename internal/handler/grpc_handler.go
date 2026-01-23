package handler

import (
	"context"

	"github.com/pesio-ai/be-go-common/logger"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	"github.com/pesio-ai/be-identity-service/internal/service"
	pb "github.com/pesio-ai/be-go-proto/gen/go/platform/proto/platform"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GRPCHandler implements the gRPC Identity Service
type GRPCHandler struct {
	pb.UnimplementedIdentityServiceServer
	service *service.IdentityService
	log     *logger.Logger
}

// NewGRPCHandler creates a new gRPC handler
func NewGRPCHandler(service *service.IdentityService, log *logger.Logger) *GRPCHandler {
	return &GRPCHandler{
		service: service,
		log:     log,
	}
}

// Login handles login requests
func (h *GRPCHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	h.log.Info().Str("email", req.Email).Msg("Login request")

	resp, err := h.service.Login(ctx, &service.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("Login failed")
		return nil, err
	}

	return &pb.LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		User:         userToProto(resp.User),
	}, nil
}

// Logout handles logout requests
func (h *GRPCHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.Response, error) {
	h.log.Info().Str("user_id", req.UserId).Msg("Logout request")

	err := h.service.Logout(ctx, req.UserId)
	if err != nil {
		return &pb.Response{Success: false, Message: err.Error()}, err
	}

	return &pb.Response{Success: true, Message: "Logged out successfully"}, nil
}

// RefreshToken handles refresh token requests
func (h *GRPCHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.LoginResponse, error) {
	h.log.Info().Msg("Refresh token request")

	resp, err := h.service.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		h.log.Error().Err(err).Msg("Refresh token failed")
		return nil, err
	}

	return &pb.LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		User:         userToProto(resp.User),
	}, nil
}

// ValidateToken handles token validation requests
func (h *GRPCHandler) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	userID, permissions, err := h.service.ValidateToken(ctx, req.AccessToken)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:       true,
		UserId:      userID,
		Permissions: permissions,
	}, nil
}

// CreateUser handles create user requests
func (h *GRPCHandler) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	h.log.Info().Str("email", req.Email).Msg("Create user request")

	user, err := h.service.CreateUser(ctx,
		req.Email,
		req.Password,
		req.FirstName,
		req.LastName,
		req.EntityIds,
		req.RoleIds,
		"system", // TODO: Get from context
	)
	if err != nil {
		h.log.Error().Err(err).Msg("Create user failed")
		return nil, err
	}

	return userToProto(user), nil
}

// GetUser handles get user requests
func (h *GRPCHandler) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	user, err := h.service.GetUser(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	return userToProto(user), nil
}

// Helper function to convert repository.User to proto.User
func userToProto(user *repository.User) *pb.User {
	pbUser := &pb.User{
		Id:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    user.Status,
		EntityIds: user.EntityIDs,
		RoleIds:   user.RoleIDs,
	}

	if user.LastLoginAt != nil {
		// Parse timestamp if needed
	}

	if user.CreatedAt != "" {
		// Parse and set
	}

	return pbUser
}
