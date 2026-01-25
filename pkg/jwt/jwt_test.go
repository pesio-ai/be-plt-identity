package jwt

import (
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	
	if privateKeyPEM == "" {
		t.Error("GenerateKeyPair() returned empty private key")
	}
	if publicKeyPEM == "" {
		t.Error("GenerateKeyPair() returned empty public key")
	}
	
	// Verify keys are in PEM format
	if len(privateKeyPEM) < 100 {
		t.Error("Private key seems too short")
	}
	if len(publicKeyPEM) < 100 {
		t.Error("Public key seems too short")
	}
}

func TestNewManager(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	manager, err := NewManager(privateKeyPEM, publicKeyPEM, 15*time.Minute, 7*24*time.Hour)
	if err != nil {
		t.Errorf("NewManager() error = %v", err)
		return
	}
	
	if manager == nil {
		t.Error("NewManager() returned nil manager")
	}
	if manager.privateKey == nil {
		t.Error("NewManager() private key is nil")
	}
	if manager.publicKey == nil {
		t.Error("NewManager() public key is nil")
	}
}

func TestNewManagerInvalidKeys(t *testing.T) {
	tests := []struct {
		name          string
		privateKeyPEM string
		publicKeyPEM  string
		wantErr       bool
	}{
		{
			name:          "empty private key",
			privateKeyPEM: "",
			publicKeyPEM:  "valid-key",
			wantErr:       true,
		},
		{
			name:          "empty public key",
			privateKeyPEM: "valid-key",
			publicKeyPEM:  "",
			wantErr:       true,
		},
		{
			name:          "invalid private key",
			privateKeyPEM: "not-a-valid-key",
			publicKeyPEM:  "not-a-valid-key",
			wantErr:       true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewManager(tt.privateKeyPEM, tt.publicKeyPEM, 15*time.Minute, 7*24*time.Hour)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateTokenPair(t *testing.T) {
	manager := setupTestManager(t)
	
	userID := "user-123"
	entityID := "entity-456"
	sessionID := "session-789"
	email := "test@example.com"
	
	tokenPair, err := manager.GenerateTokenPair(userID, entityID, sessionID, email)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}
	
	if tokenPair.AccessToken == "" {
		t.Error("GenerateTokenPair() returned empty access token")
	}
	if tokenPair.RefreshToken == "" {
		t.Error("GenerateTokenPair() returned empty refresh token")
	}
	if tokenPair.ExpiresIn <= 0 {
		t.Error("GenerateTokenPair() returned invalid ExpiresIn")
	}
	
	// Tokens should be different
	if tokenPair.AccessToken == tokenPair.RefreshToken {
		t.Error("Access and refresh tokens should be different")
	}
}

func TestValidateToken(t *testing.T) {
	manager := setupTestManager(t)
	
	userID := "user-123"
	entityID := "entity-456"
	sessionID := "session-789"
	email := "test@example.com"
	
	tokenPair, err := manager.GenerateTokenPair(userID, entityID, sessionID, email)
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}
	
	// Validate access token
	claims, err := manager.ValidateToken(tokenPair.AccessToken)
	if err != nil {
		t.Errorf("ValidateToken() error = %v", err)
		return
	}
	
	if claims.UserID != userID {
		t.Errorf("ValidateToken() UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.EntityID != entityID {
		t.Errorf("ValidateToken() EntityID = %v, want %v", claims.EntityID, entityID)
	}
	if claims.SessionID != sessionID {
		t.Errorf("ValidateToken() SessionID = %v, want %v", claims.SessionID, sessionID)
	}
	if claims.Email != email {
		t.Errorf("ValidateToken() Email = %v, want %v", claims.Email, email)
	}
	if claims.TokenType != "access" {
		t.Errorf("ValidateToken() TokenType = %v, want access", claims.TokenType)
	}
}

func TestValidateRefreshToken(t *testing.T) {
	manager := setupTestManager(t)
	
	tokenPair, err := manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}
	
	// Validate refresh token
	claims, err := manager.ValidateToken(tokenPair.RefreshToken)
	if err != nil {
		t.Errorf("ValidateToken() error = %v", err)
		return
	}
	
	if claims.TokenType != "refresh" {
		t.Errorf("ValidateToken() TokenType = %v, want refresh", claims.TokenType)
	}
}

func TestValidateInvalidToken(t *testing.T) {
	manager := setupTestManager(t)
	
	tests := []struct {
		name      string
		token     string
		wantError error
	}{
		{
			name:      "empty token",
			token:     "",
			wantError: ErrInvalidToken,
		},
		{
			name:      "malformed token",
			token:     "not.a.valid.token",
			wantError: ErrInvalidToken,
		},
		{
			name:      "random string",
			token:     "random-string-not-jwt",
			wantError: ErrInvalidToken,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.ValidateToken(tt.token)
			if err == nil {
				t.Error("ValidateToken() expected error, got nil")
			}
		})
	}
}

func TestValidateExpiredToken(t *testing.T) {
	// Create manager with very short token duration
	privateKeyPEM, publicKeyPEM, _ := GenerateKeyPair()
	manager, err := NewManager(privateKeyPEM, publicKeyPEM, 1*time.Millisecond, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	
	tokenPair, err := manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}
	
	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)
	
	_, err = manager.ValidateToken(tokenPair.AccessToken)
	if err != ErrTokenExpired {
		t.Errorf("ValidateToken() error = %v, want ErrTokenExpired", err)
	}
}

func TestTokensUniqueness(t *testing.T) {
	manager := setupTestManager(t)
	
	// Generate multiple token pairs with same data
	tokenPair1, _ := manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	tokenPair2, _ := manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	
	// Tokens should be different due to unique JTI (JWT ID) and timestamps
	if tokenPair1.AccessToken == tokenPair2.AccessToken {
		t.Error("Generated identical access tokens (should be unique)")
	}
	if tokenPair1.RefreshToken == tokenPair2.RefreshToken {
		t.Error("Generated identical refresh tokens (should be unique)")
	}
}

func TestTokenClaimsComplete(t *testing.T) {
	manager := setupTestManager(t)
	
	tokenPair, err := manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}
	
	claims, err := manager.ValidateToken(tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	
	// Check all standard claims are set
	if claims.ID == "" {
		t.Error("Claims.ID (JTI) is empty")
	}
	if claims.Issuer != "pesio-finance-erp" {
		t.Errorf("Claims.Issuer = %v, want pesio-finance-erp", claims.Issuer)
	}
	if claims.IssuedAt == nil {
		t.Error("Claims.IssuedAt is nil")
	}
	if claims.ExpiresAt == nil {
		t.Error("Claims.ExpiresAt is nil")
	}
	if claims.NotBefore == nil {
		t.Error("Claims.NotBefore is nil")
	}
}

func BenchmarkGenerateTokenPair(b *testing.B) {
	manager := setupTestManager(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	}
}

func BenchmarkValidateToken(b *testing.B) {
	manager := setupTestManager(&testing.T{})
	tokenPair, _ := manager.GenerateTokenPair("user-123", "entity-456", "session-789", "test@example.com")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.ValidateToken(tokenPair.AccessToken)
	}
}

// Helper function to set up test manager
func setupTestManager(t *testing.T) *Manager {
	privateKeyPEM, publicKeyPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	manager, err := NewManager(privateKeyPEM, publicKeyPEM, 15*time.Minute, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	
	return manager
}
