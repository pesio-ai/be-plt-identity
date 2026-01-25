package test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pesio-ai/be-lib-common/logger"
	pb "github.com/pesio-ai/be-lib-proto/gen/go/platform"
	"github.com/pesio-ai/be-plt-identity/internal/handler"
	"github.com/pesio-ai/be-plt-identity/internal/repository"
	"github.com/pesio-ai/be-plt-identity/internal/service"
	jwtpkg "github.com/pesio-ai/be-plt-identity/pkg/jwt"
)

// Test entity ID from bootstrap
const testEntityID = "b912b3e0-523e-46a2-9a90-587bc6c95cfa"

func setupTestEnv(t *testing.T) (*handler.GRPCHandler, *jwtpkg.Manager) {
	// Connect to test database
	dbURL := "postgres://pesio:dev_password_change_me@localhost:5432/plt_identity_db?sslmode=disable"
	dbPool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize logger
	log := logger.New(logger.Config{
		Level:       "error", // Reduce noise in tests
		ServiceName: "identity-service-test",
	})

	// Generate JWT keys
	privateKeyPEM, publicKeyPEM, err := jwtpkg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate JWT keys: %v", err)
	}

	jwtManager, err := jwtpkg.NewManager(privateKeyPEM, publicKeyPEM, 15*time.Minute, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT manager: %v", err)
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(dbPool, log)
	roleRepo := repository.NewRoleRepository(dbPool, log)
	sessionRepo := repository.NewSessionRepository(dbPool, log)

	// Initialize services
	authService := service.NewAuthService(userRepo, roleRepo, sessionRepo, jwtManager, log)
	userService := service.NewUserService(userRepo, roleRepo, log)
	roleService := service.NewRoleService(roleRepo, log)

	// Initialize handler
	grpcHandler := handler.NewGRPCHandler(authService, userService, roleService, log)

	return grpcHandler, jwtManager
}

func TestLoginFlow(t *testing.T) {
	handler, jwtManager := setupTestEnv(t)
	ctx := context.Background()

	t.Run("successful login with admin user", func(t *testing.T) {
		req := &pb.LoginRequest{
			Email:        "admin@test.com",
			Password:     "Admin123!",
			EntityDomain: testEntityID,
			DeviceType:   "web",
			DeviceName:   "test-browser",
			IpAddress:    "127.0.0.1",
		}

		resp, err := handler.Login(ctx, req)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("Login returned empty access token")
		}
		if resp.RefreshToken == "" {
			t.Error("Login returned empty refresh token")
		}
		if resp.User == nil {
			t.Error("Login returned nil user")
		}
		if resp.User.Email != "admin@test.com" {
			t.Errorf("User email = %v, want admin@test.com", resp.User.Email)
		}
		if resp.Session == nil {
			t.Error("Login returned nil session")
		}

		// Validate the access token
		claims, err := jwtManager.ValidateToken(resp.AccessToken)
		if err != nil {
			t.Errorf("Failed to validate access token: %v", err)
		}
		if claims.Email != "admin@test.com" {
			t.Errorf("Token email = %v, want admin@test.com", claims.Email)
		}
	})

	t.Run("failed login with invalid password", func(t *testing.T) {
		req := &pb.LoginRequest{
			Email:        "admin@test.com",
			Password:     "WrongPassword",
			EntityDomain: testEntityID,
			DeviceType:   "web",
		}

		_, err := handler.Login(ctx, req)
		if err == nil {
			t.Error("Login should have failed with invalid password")
		}
	})

	t.Run("failed login with non-existent user", func(t *testing.T) {
		req := &pb.LoginRequest{
			Email:        "nonexistent@test.com",
			Password:     "SomePassword",
			EntityDomain: testEntityID,
			DeviceType:   "web",
		}

		_, err := handler.Login(ctx, req)
		if err == nil {
			t.Error("Login should have failed with non-existent user")
		}
	})
}

func TestPermissions(t *testing.T) {
	handler, _ := setupTestEnv(t)
	ctx := context.Background()

	// Login to get user ID
	loginReq := &pb.LoginRequest{
		Email:        "admin@test.com",
		Password:     "Admin123!",
		EntityDomain: testEntityID,
		DeviceType:   "web",
	}

	loginResp, err := handler.Login(ctx, loginReq)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	userID := loginResp.User.Id

	t.Run("get user permissions", func(t *testing.T) {
		req := &pb.GetUserPermissionsRequest{
			UserId:   userID,
			EntityId: testEntityID,
		}

		resp, err := handler.GetUserPermissions(ctx, req)
		if err != nil {
			t.Fatalf("GetUserPermissions failed: %v", err)
		}

		if len(resp.Permissions) == 0 {
			t.Error("Admin user should have permissions")
		}

		// Admin should have all permissions
		if len(resp.Permissions) < 30 {
			t.Errorf("Admin should have at least 30 permissions, got %d", len(resp.Permissions))
		}
	})

	t.Run("check specific permission - allowed", func(t *testing.T) {
		req := &pb.CheckPermissionRequest{
			UserId:   userID,
			EntityId: testEntityID,
			Module:   "gl",
			Resource: "accounts",
			Action:   "create",
		}

		resp, err := handler.CheckPermission(ctx, req)
		if err != nil {
			t.Fatalf("CheckPermission failed: %v", err)
		}

		if !resp.Allowed {
			t.Error("Admin should have gl:accounts:create permission")
		}
	})
}
