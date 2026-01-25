package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pesio-ai/be-lib-common/logger"
	pb "github.com/pesio-ai/be-lib-proto/gen/go/platform"
	"github.com/pesio-ai/be-identity-service/internal/handler"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	"github.com/pesio-ai/be-identity-service/internal/service"
	jwtpkg "github.com/pesio-ai/be-identity-service/pkg/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Initialize logger
	log := logger.New(logger.Config{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "identity-service",
	})

	// Get configuration from environment
	dbURL := getEnv("DATABASE_URL", "postgres://pesio:dev_password_change_me@localhost:5432/plt_identity_db?sslmode=disable")
	grpcPort := getEnv("GRPC_PORT", "9081")
	
	// JWT configuration
	accessTokenDuration := 15 * time.Minute
	refreshTokenDuration := 30 * 24 * time.Hour
	
	// For MVP, generate keys on startup (in production, load from secure storage)
	privateKeyPEM := getEnv("JWT_PRIVATE_KEY", "")
	publicKeyPEM := getEnv("JWT_PUBLIC_KEY", "")
	
	if privateKeyPEM == "" || publicKeyPEM == "" {
		log.Info().Msg("Generating JWT key pair (development mode)")
		var err error
		privateKeyPEM, publicKeyPEM, err = jwtpkg.GenerateKeyPair()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to generate JWT key pair")
		}
		log.Info().Msg("JWT key pair generated successfully")
	}

	// Initialize database connection
	log.Info().Str("database", dbURL).Msg("Connecting to database")
	dbPool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer dbPool.Close()

	// Test database connection
	if err := dbPool.Ping(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed to ping database")
	}
	log.Info().Msg("Database connection established")

	// Initialize JWT manager
	jwtManager, err := jwtpkg.NewManager(privateKeyPEM, publicKeyPEM, accessTokenDuration, refreshTokenDuration)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create JWT manager")
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

	// Setup gRPC server
	grpcServer := grpc.NewServer()
	pb.RegisterIdentityServiceServer(grpcServer, grpcHandler)
	reflection.Register(grpcServer)

	// Create gRPC listener
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%s", grpcPort))
	if err != nil {
		log.Fatal().Err(err).Str("port", grpcPort).Msg("Failed to create gRPC listener")
	}

	// Start gRPC server
	go func() {
		log.Info().Str("port", grpcPort).Msg("Starting gRPC server")
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Error().Err(err).Msg("gRPC server failed")
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down gracefully...")

	// Shutdown gRPC server
	grpcServer.GracefulStop()

	log.Info().Msg("Server stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
