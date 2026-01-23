package handler

import (
	"encoding/json"
	"net/http"

	"github.com/pesio-ai/be-go-common/logger"
	"github.com/pesio-ai/be-identity-service/internal/service"
)

// HTTPHandler handles HTTP requests
type HTTPHandler struct {
	service *service.IdentityService
	log     *logger.Logger
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(service *service.IdentityService, log *logger.Logger) *HTTPHandler {
	return &HTTPHandler{
		service: service,
		log:     log,
	}
}

// Login handles login HTTP requests
func (h *HTTPHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req service.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := h.service.Login(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Logout handles logout HTTP requests
func (h *HTTPHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Extract user ID from JWT token in Authorization header
	userID := r.Header.Get("X-User-ID") // Temporary placeholder

	if err := h.service.Logout(r.Context(), userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// RefreshToken handles refresh token HTTP requests
func (h *HTTPHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := h.service.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListUsers handles list users HTTP requests
func (h *HTTPHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Parse query parameters for pagination
	page := 1
	pageSize := 20

	users, total, err := h.service.ListUsers(r.Context(), "", "", page, pageSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
		"total": total,
		"page":  page,
	})
}

// CreateUser handles create user HTTP requests
func (h *HTTPHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email     string   `json:"email"`
		Password  string   `json:"password"`
		FirstName string   `json:"first_name"`
		LastName  string   `json:"last_name"`
		EntityIDs []string `json:"entity_ids"`
		RoleIDs   []string `json:"role_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.service.CreateUser(r.Context(),
		req.Email,
		req.Password,
		req.FirstName,
		req.LastName,
		req.EntityIDs,
		req.RoleIDs,
		"system", // TODO: Get from JWT token
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}
