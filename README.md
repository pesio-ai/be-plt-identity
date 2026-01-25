# be-identity-service

Identity and authentication service (PLT-1) for Pesio Finance ERP.

## Overview

This service provides:
- User authentication and management
- JWT-based access and refresh tokens
- Role-based access control (RBAC)
- Multi-entity user access
- Authentication audit logging

## Architecture

**Service**: Platform Service PLT-1
**Database**: `plt_identity_db` (PostgreSQL with pgcrypto extension)
**gRPC Port**: 9090
**HTTP Port**: 8080

## Features

### Authentication
- Email/password login
- JWT access tokens (1 hour expiration)
- Refresh tokens (7 days expiration)
- Token validation
- Logout with token revocation

### User Management
- Create/read/update/delete users
- List users with pagination
- User status management (active, inactive, suspended)
- Multi-entity access assignment

### Authorization
- Role-based access control (RBAC)
- Permission checking
- Pre-defined roles (Super Admin, Accountant, AP Clerk, AP Manager, Viewer)
- Granular permissions across modules (identity, gl, ap, ar, br)

### Audit Trail
- Authentication event logging
- Login success/failure tracking
- IP address and user agent tracking

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 16+ (with pgcrypto extension)
- Redis/Valkey
- NATS JetStream (optional)

### Setup

1. **Clone the repository**:
```bash
cd /Users/chirag/uno360/finance_erp
git clone https://github.com/pesio-ai/be-identity-service
cd be-identity-service
```

2. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your database credentials
```

3. **Run database migrations**:
```bash
psql -h localhost -U pesio -d plt_identity_db -f migrations/001_initial_schema.sql
```

4. **Install dependencies**:
```bash
go mod download
```

5. **Bootstrap test data** (development only):
```bash
cd scripts
go run bootstrap.go
```

This creates 3 test users:
- **Admin**: `admin@test.com` / `Admin123!` (system_admin role)
- **Accountant**: `accountant@test.com` / `Accountant123!` (accountant role)
- **AP Clerk**: `clerk@test.com` / `Clerk123!` (ap_clerk role)

6. **Run the service**:
```bash
go run cmd/server/main.go
```

The service will start on:
- gRPC: localhost:9081

### Test the Service

```bash
# Login as admin
grpcurl -plaintext -d '{
  "email": "admin@test.com",
  "password": "Admin123!",
  "entity_domain": "b912b3e0-523e-46a2-9a90-587bc6c95cfa",
  "device_type": "web",
  "device_name": "test-browser",
  "ip_address": "127.0.0.1"
}' localhost:9081 platform.IdentityService/Login
```

## API Endpoints

### HTTP REST API

#### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Refresh access token

#### Users
- `POST /api/v1/users/create` - Create new user
- `GET /api/v1/users` - List users (with pagination)

#### Health
- `GET /health` - Health check

### gRPC API

See `proto/platform/identity.proto` for full gRPC service definition:
- `Login` - Authenticate user
- `Logout` - Logout user
- `RefreshToken` - Refresh access token
- `ValidateToken` - Validate access token
- `CreateUser` - Create user
- `GetUser` - Get user by ID
- `UpdateUser` - Update user
- `DeleteUser` - Delete user
- `ListUsers` - List users
- `CreateRole` - Create role
- `GetRole` - Get role
- `ListRoles` - List roles
- `AssignRole` - Assign role to user
- `RevokeRole` - Revoke role from user
- `CheckPermission` - Check user permission

## Database Schema

### Tables
- `users` - User accounts
- `roles` - User roles
- `permissions` - System permissions
- `role_permissions` - Role-permission assignments
- `user_roles` - User-role assignments
- `user_entities` - User-entity access (multi-tenant)
- `refresh_tokens` - JWT refresh tokens
- `auth_audit_log` - Authentication event log

### Default Roles
- **Super Admin**: Full system access
- **Accountant**: Full GL and financial access
- **AP Clerk**: AP data entry
- **AP Manager**: AP management and approvals
- **Viewer**: Read-only access

### Default Permissions
Permissions are organized by module:
- `user.*` - User management
- `role.*` - Role management
- `gl.*` - General Ledger
- `ap.*` - Accounts Payable

## Configuration

Environment variables (see `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVICE_NAME` | Service name | `be-identity-service` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `plt_identity_db` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `NATS_URL` | NATS server URL | `nats://localhost:4222` |
| `SERVER_PORT` | HTTP server port | `8080` |
| `GRPC_PORT` | gRPC server port | `9090` |
| `LOG_LEVEL` | Logging level | `info` |

## Development

### Run Locally
```bash
# Start dependencies (from infrastructure/)
cd ../infrastructure
make up

# Run service
cd ../be-identity-service
go run cmd/server/main.go
```

### Run Tests

**Unit Tests** (password and JWT utilities):
```bash
go test ./pkg/password -v
go test ./pkg/jwt -v
```

**Integration Tests** (full authentication flows):
```bash
cd test
go test -v
```

**All Tests**:
```bash
go test ./...
```

### Database Migrations
```bash
# Apply migrations
psql -h localhost -U pesio -d plt_identity_db -f migrations/001_initial_schema.sql
```

## Docker

### Build
```bash
docker build -t pesio-ai/be-identity-service:latest .
```

### Run
```bash
docker run -p 8080:8080 -p 9090:9090 \
  -e DB_HOST=host.docker.internal \
  -e DB_NAME=plt_identity_db \
  pesio-ai/be-identity-service:latest
```

## Security

- **Password Hashing**: Argon2id with 64MB memory, 3 iterations (OWASP recommended)
- **JWT Tokens**: RS256 asymmetric signing (2048-bit RSA keys)
- **Access Tokens**: 15-minute expiration
- **Refresh Tokens**: 30-day expiration, single-use, hashed before storage
- **Session Tracking**: Full device and IP tracking
- **Audit Logging**: All authentication events logged

**Production Checklist**:
- [ ] Set `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` environment variables (load from secure storage)
- [ ] Enable HTTPS/TLS
- [ ] Configure rate limiting (10 failed logins per IP per 15 minutes)
- [ ] Enable database SSL mode
- [ ] Set strong database passwords
- [ ] Review CORS settings
- [ ] Rotate JWT keys periodically
- [ ] Monitor auth_audit_log for suspicious activity

## Dependencies

- **be-go-common**: Shared utilities (database, redis, logger, errors)
- **be-go-proto**: Protocol buffer definitions
- **golang-jwt/jwt**: JWT token generation
- **golang.org/x/crypto**: Password hashing
- **google.golang.org/grpc**: gRPC server

## License

Proprietary - Pesio AI
