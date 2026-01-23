package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pesio-ai/be-go-common/config"
	"github.com/pesio-ai/be-go-common/database"
	"github.com/pesio-ai/be-go-common/logger"
	"github.com/pesio-ai/be-go-common/middleware"
	"github.com/pesio-ai/be-go-common/nats"
	"github.com/pesio-ai/be-go-common/redis"
	"github.com/pesio-ai/be-identity-service/internal/handler"
	"github.com/pesio-ai/be-identity-service/internal/repository"
	"github.com/pesio-ai/be-identity-service/internal/service"
	pb "github.com/pesio-ai/be-go-proto/gen/go/platform/proto/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(logger.Config{
		Level:       os.Getenv("LOG_LEVEL"),
		Environment: cfg.Service.Environment,
		ServiceName: cfg.Service.Name,
		Version:     cfg.Service.Version,
	})

	log.Info().
		Str("service", cfg.Service.Name).
		Str("version", cfg.Service.Version).
		Str("environment", cfg.Service.Environment).
		Msg("Starting Identity Service")

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database
	db, err := database.New(ctx, database.Config{
		Host:        cfg.Database.Host,
		Port:        cfg.Database.Port,
		User:        cfg.Database.User,
		Password:    cfg.Database.Password,
		Database:    cfg.Database.Database,
		SSLMode:     cfg.Database.SSLMode,
		MaxConns:    cfg.Database.MaxConns,
		MinConns:    cfg.Database.MinConns,
		MaxConnTime: cfg.Database.MaxConnTime,
		MaxIdleTime: cfg.Database.MaxIdleTime,
		HealthCheck: cfg.Database.HealthCheck,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()
	log.Info().Msg("Database connection established")

	// Initialize Redis
	redisClient, err := redis.New(redis.Config{
		Host:         cfg.Redis.Host,
		Port:         cfg.Redis.Port,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		MaxRetries:   cfg.Redis.MaxRetries,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	}
	defer redisClient.Close()
	log.Info().Msg("Redis connection established")

	// Initialize NATS (optional - for event publishing)
	var natsClient *nats.Client
	if cfg.NATS.URL != "" {
		natsClient, err = nats.New(nats.Config{
			URL:           cfg.NATS.URL,
			MaxReconnects: cfg.NATS.MaxReconnects,
			ReconnectWait: cfg.NATS.ReconnectWait,
			Token:         cfg.NATS.Token,
			StreamName:    "IDENTITY_EVENTS",
		})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to connect to NATS (continuing without event publishing)")
		} else {
			defer natsClient.Close()
			log.Info().Msg("NATS connection established")
		}
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	tokenRepo := repository.NewTokenRepository(db)

	// Initialize services
	identityService := service.NewIdentityService(
		userRepo,
		roleRepo,
		tokenRepo,
		redisClient,
		log,
	)

	// Start gRPC server
	grpcServer := grpc.NewServer()
	pb.RegisterIdentityServiceServer(grpcServer, handler.NewGRPCHandler(identityService, log))
	reflection.Register(grpcServer)

	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to listen for gRPC")
	}

	go func() {
		log.Info().Int("port", cfg.Server.GRPCPort).Msg("Starting gRPC server")
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.Error().Err(err).Msg("gRPC server failed")
		}
	}()

	// Start HTTP server
	httpHandler := handler.NewHTTPHandler(identityService, log)
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// API routes
	mux.HandleFunc("/api/v1/auth/login", httpHandler.Login)
	mux.HandleFunc("/api/v1/auth/logout", httpHandler.Logout)
	mux.HandleFunc("/api/v1/auth/refresh", httpHandler.RefreshToken)
	mux.HandleFunc("/api/v1/users", httpHandler.ListUsers)
	mux.HandleFunc("/api/v1/users/create", httpHandler.CreateUser)

	// Apply middleware
	var h http.Handler = mux
	h = middleware.RequestID(h)
	h = middleware.Logger(&log.Logger)(h)
	h = middleware.Recovery(&log.Logger)(h)
	h = middleware.CORS([]string{"*"})(h)
	h = middleware.Timeout(30 * time.Second)(h)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      h,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		log.Info().Int("port", cfg.Server.Port).Msg("Starting HTTP server")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTP server failed")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down servers...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown failed")
	}

	grpcServer.GracefulStop()

	log.Info().Msg("Servers stopped")
}
