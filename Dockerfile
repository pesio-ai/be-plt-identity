# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /build

# Copy shared libraries first
COPY be-lib-common/ ./be-lib-common/
COPY be-lib-proto/ ./be-lib-proto/

# Copy service files
COPY be-plt-identity/ ./be-plt-identity/

# Build from service directory
WORKDIR /build/be-plt-identity

# Download dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Runtime stage
FROM alpine:latest

# Install ca-certificates
RUN apk --no-cache add ca-certificates curl

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /build/be-plt-identity/main .

# Copy migrations
COPY --from=builder /build/be-plt-identity/migrations ./migrations

# Expose ports (gRPC only)
EXPOSE 9080

# Health check (gRPC doesn't have simple HTTP health endpoint)
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD sh -c "nc -z localhost 9080 || exit 1"

# Run the server
CMD ["./main"]
