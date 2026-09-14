package password_manager

import (
	"errors"
	"net/http"
	"strings"
	"time"

	service "crypt-pass/internal/password_manager/service"
	"crypt-pass/pkg/middleware"
	"crypt-pass/pkg/response"

	"github.com/google/uuid"
)

type PasswordManagerHandler struct {
	passwordManagerService service.PasswordManagerService
}

func NewPasswordManagerHandler(passwordManagerService service.PasswordManagerService) *PasswordManagerHandler {
	return &PasswordManagerHandler{
		passwordManagerService: passwordManagerService,
	}
}

type CreatePasswordRequest struct {
	Title     string `json:"title"`
	Password  string `json:"password"` // Password terpilih hasil generate
	Clue      string `json:"clue,omitempty"`
	MasterKey string `json:"master_key,omitempty"`
}

func (r *CreatePasswordRequest) Validate() error {
	if strings.TrimSpace(r.Title) == "" {
		return errors.New("title is required")
	}
	if strings.TrimSpace(r.Password) == "" {
		return errors.New("password is required")
	}
	return nil
}

type DeletePasswordRequest struct {
	ID string `json:"id"`
}

type PasswordResponse struct {
	ID                uuid.UUID `json:"id"`
	UserID            uuid.UUID `json:"user_id"`
	Title             string    `json:"title"`
	Clue              string    `json:"clue,omitempty"`
	PasswordEncrypted string    `json:"password_encrypted,omitempty"`
	IsDeleted         bool      `json:"is_deleted"`
	IsDirty           bool      `json:"is_dirty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

const defaultSuggestionCount = 3

type GeneratePasswordRequest struct {
	Password string `json:"password"` // input kata yang ingin dijadikan password (cth: "nasigoreng")
}

func (r *GeneratePasswordRequest) Validate() error {
	if strings.TrimSpace(r.Password) == "" {
		return errors.New("password is required")
	}
	return nil
}

type GeneratePasswordResponse struct {
	Suggestions []string `json:"suggestions"`
	Password    string   `json:"password"` // Kata dasar input user (cth: "nasigoreng")
	Count       int      `json:"count"`
}

// HandlePasswords dispatches /api/v1/passwords requests by HTTP method
func (h *PasswordManagerHandler) HandlePasswords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.GetPasswords(w, r)
	case http.MethodPost:
		h.CreatePassword(w, r)
	case http.MethodDelete:
		h.DeletePassword(w, r)
	default:
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// GeneratePassword menyediakan endpoint untuk men-generate 3 pilihan saran password unik berbasis profil
func (h *PasswordManagerHandler) GeneratePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req GeneratePasswordRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ditetapkan pasti 3 opsi demi keamanan dan kestabilan performa server
	suggestions, err := h.passwordManagerService.GenerateMultiplePasswords(r.Context(), req.Password, "", defaultSuggestionCount)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := GeneratePasswordResponse{
		Suggestions: suggestions,
		Password:    req.Password,
		Count:       len(suggestions),
	}

	response.JSON(w, http.StatusOK, resp, "Password suggestions generated successfully")
}

// CreatePassword menyimpan entitas password baru. Jika password tidak diisi, dibuat secara otomatis berdasarkan profil user.
func (h *PasswordManagerHandler) CreatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req CreatePasswordRequest
	if err := response.DecodeJSON(r, &req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	cred, err := h.passwordManagerService.CreatePassword(r.Context(), userID, req.Title, req.Clue, req.Password, req.MasterKey)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := PasswordResponse{
		ID:                cred.ID,
		UserID:            cred.UserID,
		Title:             cred.Title,
		Clue:              cred.Clue,
		PasswordEncrypted: cred.PasswordEncrypted,
		IsDeleted:         cred.IsDeleted,
		IsDirty:           cred.IsDirty,
		CreatedAt:         cred.CreatedAt,
		UpdatedAt:         cred.UpdatedAt,
	}

	response.JSON(w, http.StatusCreated, resp, "Password created successfully")
}

// GetPasswords mengambil satu atau seluruh list password milik user yang belum dihapus
func (h *PasswordManagerHandler) GetPasswords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	query := r.URL.Query()
	idStr := query.Get("id")
	title := query.Get("title")

	if idStr != "" {
		id, err := uuid.Parse(idStr)
		if err != nil {
			response.Error(w, http.StatusBadRequest, "Invalid password ID format")
			return
		}

		cred, err := h.passwordManagerService.GetPassword(r.Context(), userID, id)
		if err != nil || cred == nil {
			response.Error(w, http.StatusNotFound, "Password not found")
			return
		}

		resp := PasswordResponse{
			ID:                cred.ID,
			UserID:            cred.UserID,
			Title:             cred.Title,
			Clue:              cred.Clue,
			PasswordEncrypted: cred.PasswordEncrypted,
			IsDeleted:         cred.IsDeleted,
			IsDirty:           cred.IsDirty,
			CreatedAt:         cred.CreatedAt,
			UpdatedAt:         cred.UpdatedAt,
		}
		response.JSON(w, http.StatusOK, resp, "Password retrieved successfully")
		return
	}

	if title != "" {
		cred, err := h.passwordManagerService.GetPasswordByTitle(r.Context(), userID, title)
		if err != nil || cred == nil {
			response.Error(w, http.StatusNotFound, "Password not found")
			return
		}

		resp := PasswordResponse{
			ID:                cred.ID,
			UserID:            cred.UserID,
			Title:             cred.Title,
			Clue:              cred.Clue,
			PasswordEncrypted: cred.PasswordEncrypted,
			IsDeleted:         cred.IsDeleted,
			IsDirty:           cred.IsDirty,
			CreatedAt:         cred.CreatedAt,
			UpdatedAt:         cred.UpdatedAt,
		}
		response.JSON(w, http.StatusOK, resp, "Password retrieved successfully")
		return
	}

	creds, err := h.passwordManagerService.GetAllPasswords(r.Context(), userID)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	var respList []PasswordResponse
	for _, cred := range creds {
		respList = append(respList, PasswordResponse{
			ID:        cred.ID,
			UserID:    cred.UserID,
			Title:     cred.Title,
			Clue:      cred.Clue,
			IsDeleted: cred.IsDeleted,
			IsDirty:   cred.IsDirty,
			CreatedAt: cred.CreatedAt,
			UpdatedAt: cred.UpdatedAt,
		})
	}
	if respList == nil {
		respList = []PasswordResponse{}
	}

	response.JSON(w, http.StatusOK, respList, "Passwords retrieved successfully")
}

// DeletePassword melakukan soft delete password berdasarkan ID
func (h *PasswordManagerHandler) DeletePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		response.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		var delReq DeletePasswordRequest
		if err := response.DecodeJSON(r, &delReq); err == nil {
			idStr = delReq.ID
		}
	}

	if idStr == "" {
		response.Error(w, http.StatusBadRequest, "Password ID is required")
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid password ID format")
		return
	}

	if err := h.passwordManagerService.DeletePassword(r.Context(), userID, id); err != nil {
		response.Error(w, http.StatusNotFound, "Password not found or already deleted")
		return
	}

	response.JSON(w, http.StatusOK, nil, "Password deleted successfully")
}
