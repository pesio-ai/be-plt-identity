package repository

import "time"

// User represents a user in the system
type User struct {
	ID                  string
	EntityID            string
	Email               string
	EmailVerified       bool
	PasswordHash        *string
	FirstName           string
	LastName            string
	Phone               *string
	ProfilePhotoURL     *string
	Timezone            string
	Locale              string
	Status              string
	UserType            string
	LastLoginAt         *time.Time
	FailedLoginAttempts int
	LockedUntil         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	CreatedBy           *string
	UpdatedBy           *string
}

// Role represents a role that can be assigned to users
type Role struct {
	ID          string
	EntityID    *string // NULL for system-wide roles
	Name        string
	DisplayName string
	Description *string
	RoleType    string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   *string
	UpdatedBy   *string
}

// Permission represents a specific permission
type Permission struct {
	ID          string
	Module      string
	Resource    string
	Action      string
	Name        string
	Description *string
	IsSensitive bool
	CreatedAt   time.Time
}

// UserRole represents the assignment of a role to a user
type UserRole struct {
	UserID     string
	RoleID     string
	EntityID   string
	AssignedAt time.Time
	AssignedBy *string
}

// Session represents a user session
type Session struct {
	ID                     string
	UserID                 string
	EntityID               string
	DeviceType             *string
	DeviceName             *string
	IPAddress              *string
	UserAgent              *string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	LastActivityAt         time.Time
	IsActive               bool
	RefreshTokenHash       *string
	RefreshTokenExpiresAt  *time.Time
}

// RolePermission represents the assignment of a permission to a role
type RolePermission struct {
	RoleID       string
	PermissionID string
	GrantedAt    time.Time
	GrantedBy    *string
}
