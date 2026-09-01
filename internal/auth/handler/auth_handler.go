package handler

import (
	"encoding/json"
	"net/http"

	"crypt-pass/internal/auth/service"
	"crypt-pass/pkg/middleware"
	"crypt-pass/pkg/response"

	"github.com/google/uuid"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type RegisterRequest struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	BackupSalt string `json:"backup_salt"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	BackupSalt string    `json:"backup_salt"`
}

type LoginResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		response.Error(w, http.StatusBadRequest, "Name, email, and password are required")
		return
	}

	user, err := h.authService.Register(r.Context(), req.Name, req.Email, req.Password, req.BackupSalt)
	if err != nil {
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := UserResponse{
		ID:         user.ID,
		Name:       user.Name,
		Email:      user.Email,
		BackupSalt: user.BackupSalt,
	}

	response.JSON(w, http.StatusCreated, resp, "User registered successfully")
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		response.Error(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	user, token, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, err.Error())
		return
	}

	resp := LoginResponse{
		Token: token,
		User: UserResponse{
			ID:         user.ID,
			Name:       user.Name,
			Email:      user.Email,
			BackupSalt: user.BackupSalt,
		},
	}

	response.JSON(w, http.StatusOK, resp, "Login successful")
}

func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		response.Error(w, http.StatusNotFound, "User not found")
		return
	}

	resp := UserResponse{
		ID:         user.ID,
		Name:       user.Name,
		Email:      user.Email,
		BackupSalt: user.BackupSalt,
	}

	response.JSON(w, http.StatusOK, resp, "Profile fetched successfully")
}

