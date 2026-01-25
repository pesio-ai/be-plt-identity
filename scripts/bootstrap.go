package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pesio-ai/be-identity-service/pkg/password"
)

// Bootstrap creates test data for development and testing
func main() {
	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://pesio:dev_password_change_me@localhost:5432/plt_identity_db?sslmode=disable"
	}

	ctx := context.Background()

	// Connect to database
	log.Println("Connecting to database...")
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbPool.Close()

	// Test connection
	if err := dbPool.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Database connection established")

	// Create test entity
	entityID, err := createTestEntity(ctx, dbPool)
	if err != nil {
		log.Fatalf("Failed to create test entity: %v", err)
	}
	log.Printf("✓ Created test entity: %s (domain: test.pesio.ai)", entityID)

	// Create test admin user
	adminUserID, err := createAdminUser(ctx, dbPool, entityID)
	if err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}
	log.Printf("✓ Created admin user: %s (email: admin@test.com)", adminUserID)

	// Assign system_admin role
	err = assignSystemAdminRole(ctx, dbPool, adminUserID, entityID)
	if err != nil {
		log.Fatalf("Failed to assign system_admin role: %v", err)
	}
	log.Println("✓ Assigned system_admin role to admin user")

	// Create test accountant user
	accountantUserID, err := createAccountantUser(ctx, dbPool, entityID)
	if err != nil {
		log.Fatalf("Failed to create accountant user: %v", err)
	}
	log.Printf("✓ Created accountant user: %s (email: accountant@test.com)", accountantUserID)

	// Assign accountant role
	err = assignAccountantRole(ctx, dbPool, accountantUserID, entityID)
	if err != nil {
		log.Fatalf("Failed to assign accountant role: %v", err)
	}
	log.Println("✓ Assigned accountant role to accountant user")

	// Create test AP clerk user
	clerkUserID, err := createAPClerkUser(ctx, dbPool, entityID)
	if err != nil {
		log.Fatalf("Failed to create AP clerk user: %v", err)
	}
	log.Printf("✓ Created AP clerk user: %s (email: clerk@test.com)", clerkUserID)

	// Assign AP clerk role
	err = assignAPClerkRole(ctx, dbPool, clerkUserID, entityID)
	if err != nil {
		log.Fatalf("Failed to assign AP clerk role: %v", err)
	}
	log.Println("✓ Assigned ap_clerk role to clerk user")

	log.Println("\n=== Bootstrap Complete ===")
	log.Println("Test Credentials:")
	log.Println("  Admin:      admin@test.com / Admin123!")
	log.Println("  Accountant: accountant@test.com / Accountant123!")
	log.Println("  AP Clerk:   clerk@test.com / Clerk123!")
	log.Printf("  Entity ID:  %s\n", entityID)
	log.Println("  Domain:     test.pesio.ai")
}

func createTestEntity(ctx context.Context, db *pgxpool.Pool) (string, error) {
	entityID := uuid.New().String()

	// Check if entities table exists (it's in a different database)
	// For now, we'll just return a fixed entity ID that should exist
	// In production, this would call the entity service
	
	// For testing, use a well-known entity ID
	return entityID, nil
}

func createAdminUser(ctx context.Context, db *pgxpool.Pool, entityID string) (string, error) {
	userID := uuid.New().String()
	email := "admin@test.com"
	passwordPlain := "Admin123!"

	// Hash password
	passwordHash, err := password.Hash(passwordPlain, nil)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Check if user already exists
	var existingUserID string
	err = db.QueryRow(ctx,
		"SELECT id FROM users WHERE email = $1 AND entity_id = $2",
		email, entityID,
	).Scan(&existingUserID)

	if err == nil {
		// User exists, return existing ID
		return existingUserID, nil
	}

	// Create user
	query := `
		INSERT INTO users (
			id, entity_id, email, email_verified, password_hash,
			first_name, last_name, timezone, locale, status, user_type
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`

	_, err = db.Exec(ctx, query,
		userID, entityID, email, true, passwordHash,
		"Admin", "User", "UTC", "en-US", "active", "internal",
	)

	if err != nil {
		return "", fmt.Errorf("failed to insert user: %w", err)
	}

	return userID, nil
}

func createAccountantUser(ctx context.Context, db *pgxpool.Pool, entityID string) (string, error) {
	userID := uuid.New().String()
	email := "accountant@test.com"
	passwordPlain := "Accountant123!"

	passwordHash, err := password.Hash(passwordPlain, nil)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	var existingUserID string
	err = db.QueryRow(ctx,
		"SELECT id FROM users WHERE email = $1 AND entity_id = $2",
		email, entityID,
	).Scan(&existingUserID)

	if err == nil {
		return existingUserID, nil
	}

	query := `
		INSERT INTO users (
			id, entity_id, email, email_verified, password_hash,
			first_name, last_name, timezone, locale, status, user_type
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`

	_, err = db.Exec(ctx, query,
		userID, entityID, email, true, passwordHash,
		"Test", "Accountant", "UTC", "en-US", "active", "internal",
	)

	if err != nil {
		return "", fmt.Errorf("failed to insert user: %w", err)
	}

	return userID, nil
}

func createAPClerkUser(ctx context.Context, db *pgxpool.Pool, entityID string) (string, error) {
	userID := uuid.New().String()
	email := "clerk@test.com"
	passwordPlain := "Clerk123!"

	passwordHash, err := password.Hash(passwordPlain, nil)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	var existingUserID string
	err = db.QueryRow(ctx,
		"SELECT id FROM users WHERE email = $1 AND entity_id = $2",
		email, entityID,
	).Scan(&existingUserID)

	if err == nil {
		return existingUserID, nil
	}

	query := `
		INSERT INTO users (
			id, entity_id, email, email_verified, password_hash,
			first_name, last_name, timezone, locale, status, user_type
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`

	_, err = db.Exec(ctx, query,
		userID, entityID, email, true, passwordHash,
		"Test", "Clerk", "UTC", "en-US", "active", "internal",
	)

	if err != nil {
		return "", fmt.Errorf("failed to insert user: %w", err)
	}

	return userID, nil
}

func assignSystemAdminRole(ctx context.Context, db *pgxpool.Pool, userID, entityID string) error {
	var roleID string
	err := db.QueryRow(ctx, "SELECT id FROM roles WHERE name = 'system_admin'").Scan(&roleID)
	if err != nil {
		return fmt.Errorf("failed to find system_admin role: %w", err)
	}

	query := `
		INSERT INTO user_roles (user_id, role_id, entity_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id, entity_id) DO NOTHING
	`

	_, err = db.Exec(ctx, query, userID, roleID, entityID, userID)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

func assignAccountantRole(ctx context.Context, db *pgxpool.Pool, userID, entityID string) error {
	var roleID string
	err := db.QueryRow(ctx, "SELECT id FROM roles WHERE name = 'accountant'").Scan(&roleID)
	if err != nil {
		return fmt.Errorf("failed to find accountant role: %w", err)
	}

	query := `
		INSERT INTO user_roles (user_id, role_id, entity_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id, entity_id) DO NOTHING
	`

	_, err = db.Exec(ctx, query, userID, roleID, entityID, userID)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

func assignAPClerkRole(ctx context.Context, db *pgxpool.Pool, userID, entityID string) error {
	var roleID string
	err := db.QueryRow(ctx, "SELECT id FROM roles WHERE name = 'ap_clerk'").Scan(&roleID)
	if err != nil {
		return fmt.Errorf("failed to find ap_clerk role: %w", err)
	}

	query := `
		INSERT INTO user_roles (user_id, role_id, entity_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id, entity_id) DO NOTHING
	`

	_, err = db.Exec(ctx, query, userID, roleID, entityID, userID)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}
