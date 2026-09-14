package handler

import (
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
	Name         string `json:"name"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	BirthDate    string `json:"birth_date"`
	FavoriteFood string `json:"favorite_food"`
	DreamCity    string `json:"dream_city"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	BackupSalt   string    `json:"backup_salt"`
	BirthDate    string    `json:"birth_date"`
	FavoriteFood string    `json:"favorite_food"`
	DreamCity    string    `json:"dream_city"`
}

type AuthUserResponse struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
}

type LoginResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	ExpiresIn    int64            `json:"expires_in"`
	User         AuthUserResponse `json:"user"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RecoverAccountRequest struct {
	Email        string `json:"email"`
	BackupSalt   string `json:"backup_salt"`
	BirthDate    string `json:"birth_date"`
	FavoriteFood string `json:"favorite_food"`
	DreamCity    string `json:"dream_city"`
	NewPassword  string `json:"new_password"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegisterRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" || req.BirthDate == "" || req.FavoriteFood == "" || req.DreamCity == "" {
		response.Error(w, http.StatusBadRequest, "Name, email, password, birth_date, favorite_food, and dream_city are required")
		return
	}

	user, err := h.authService.Register(r.Context(), req.Name, req.Email, req.Password, "", req.BirthDate, req.FavoriteFood, req.DreamCity)
	if err != nil {
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := UserResponse{
		ID:           user.ID,
		Name:         user.Name,
		Email:        user.Email,
		BackupSalt:   user.BackupSalt,
		BirthDate:    user.BirthDate,
		FavoriteFood: user.FavoriteFood,
		DreamCity:    user.DreamCity,
	}

	response.JSON(w, http.StatusCreated, resp, "User registered successfully")
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LoginRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		response.Error(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	user, accessToken, refreshToken, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, err.Error())
		return
	}

	resp := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900, // 15 minutes (in seconds)
		User: AuthUserResponse{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
	}

	response.JSON(w, http.StatusOK, resp, "Login successful")
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RefreshTokenRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		response.Error(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	newAccessToken, newRefreshToken, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, err.Error())
		return
	}

	resp := RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}

	response.JSON(w, http.StatusOK, resp, "Token refreshed successfully")
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LogoutRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		response.Error(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	if err := h.authService.Logout(r.Context(), req.RefreshToken); err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to logout")
		return
	}

	response.JSON(w, http.StatusOK, nil, "Logged out successfully")
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
		ID:           user.ID,
		Name:         user.Name,
		Email:        user.Email,
		BackupSalt:   user.BackupSalt,
		BirthDate:    user.BirthDate,
		FavoriteFood: user.FavoriteFood,
		DreamCity:    user.DreamCity,
	}

	response.JSON(w, http.StatusOK, resp, "Profile fetched successfully")
}

func (h *AuthHandler) RecoverAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RecoverAccountRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.BackupSalt == "" || req.BirthDate == "" || req.FavoriteFood == "" || req.DreamCity == "" || req.NewPassword == "" {
		response.Error(w, http.StatusBadRequest, "Email, backup_salt, birth_date, favorite_food, dream_city, and new_password are required")
		return
	}

	if err := h.authService.RecoverAccount(r.Context(), req.Email, req.BackupSalt, req.BirthDate, req.FavoriteFood, req.DreamCity, req.NewPassword); err != nil {
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	response.JSON(w, http.StatusOK, nil, "Account master password reset successfully")
}
