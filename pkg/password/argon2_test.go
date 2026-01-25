package password

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		params   *Params
		wantErr  bool
	}{
		{
			name:     "hash with default params",
			password: "SecurePassword123!",
			params:   nil,
			wantErr:  false,
		},
		{
			name:     "hash with custom params",
			password: "AnotherPassword456!",
			params:   &Params{Memory: 32 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32},
			wantErr:  false,
		},
		{
			name:     "hash empty password",
			password: "",
			params:   nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := Hash(tt.password, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if hash == "" {
					t.Error("Hash() returned empty string")
				}
				// Verify hash format: $argon2id$v=19$m=65536,t=3,p=2$salt$hash
				if !strings.HasPrefix(hash, "$argon2id$v=19$") {
					t.Errorf("Hash() invalid format: %s", hash)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	password := "TestPassword123!"
	hash, err := Hash(password, nil)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{
			name:     "verify correct password",
			password: password,
			hash:     hash,
			want:     true,
			wantErr:  false,
		},
		{
			name:     "verify incorrect password",
			password: "WrongPassword",
			hash:     hash,
			want:     false,
			wantErr:  false,
		},
		{
			name:     "verify with invalid hash format",
			password: password,
			hash:     "invalid-hash",
			want:     false,
			wantErr:  true,
		},
		{
			name:     "verify with missing parts",
			password: password,
			hash:     "$argon2id$v=19$m=65536",
			want:     false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashUniqueness(t *testing.T) {
	password := "SamePassword123!"
	
	hash1, err := Hash(password, nil)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	hash2, err := Hash(password, nil)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	// Hashes should be different due to random salt
	if hash1 == hash2 {
		t.Error("Hash() produced identical hashes for same password (should use different salts)")
	}
	
	// But both should verify correctly
	valid1, err := Verify(password, hash1)
	if err != nil || !valid1 {
		t.Error("Verify() failed for hash1")
	}
	
	valid2, err := Verify(password, hash2)
	if err != nil || !valid2 {
		t.Error("Verify() failed for hash2")
	}
}

func TestDecodeHash(t *testing.T) {
	// Create a valid hash
	password := "TestPassword"
	hash, err := Hash(password, nil)
	if err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}
	
	params, salt, hashBytes, err := decodeHash(hash)
	if err != nil {
		t.Errorf("decodeHash() error = %v", err)
		return
	}
	
	if params == nil {
		t.Error("decodeHash() returned nil params")
	}
	if len(salt) == 0 {
		t.Error("decodeHash() returned empty salt")
	}
	if len(hashBytes) == 0 {
		t.Error("decodeHash() returned empty hash")
	}
}

func TestInvalidHashFormat(t *testing.T) {
	invalidHashes := []string{
		"",
		"plain-text-password",
		"$bcrypt$invalid",
		"$argon2id$",
		"$argon2id$v=18$m=65536,t=3,p=2$salt$hash", // Wrong version
	}
	
	for _, hash := range invalidHashes {
		t.Run(hash, func(t *testing.T) {
			_, err := Verify("password", hash)
			if err == nil {
				t.Errorf("Verify() expected error for invalid hash: %s", hash)
			}
		})
	}
}

func BenchmarkHash(b *testing.B) {
	password := "BenchmarkPassword123!"
	params := DefaultParams()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(password, params)
	}
}

func BenchmarkVerify(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, _ := Hash(password, nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(password, hash)
	}
}
