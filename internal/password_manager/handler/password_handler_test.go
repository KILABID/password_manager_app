package password_manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crypt-pass/config"
	entity "crypt-pass/internal/password_manager/entity"
	service "crypt-pass/internal/password_manager/service"
	jwtPkg "crypt-pass/pkg/jwt"
	"crypt-pass/pkg/middleware"

	"github.com/google/uuid"
)

type mockPasswordService struct {
	generatePasswordFn                    func(ctx context.Context, clue string, masterKey string) (string, error)
	generatePasswordWithProfileFn         func(ctx context.Context, clue string, masterKey string, profile service.UserProfileContext) (string, error)
	generateMultiplePasswordsFn            func(ctx context.Context, clue string, masterKey string, count int) ([]string, error)
	generateMultiplePasswordsWithProfileFn func(ctx context.Context, clue string, masterKey string, profile service.UserProfileContext, count int) ([]string, error)
	createPasswordFn                      func(ctx context.Context, userID uuid.UUID, title, clue, password, masterKey string) (*entity.Credentials, error)
	getPasswordFn                         func(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error)
	getPasswordByTitleFn                  func(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error)
	getAllPasswordsFn                     func(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error)
	deletePasswordFn                      func(ctx context.Context, userID uuid.UUID, id uuid.UUID) error
}

func (m *mockPasswordService) CreatePassword(ctx context.Context, userID uuid.UUID, title, clue, password, masterKey string) (*entity.Credentials, error) {
	if m.createPasswordFn != nil {
		return m.createPasswordFn(ctx, userID, title, clue, password, masterKey)
	}
	return &entity.Credentials{ID: uuid.New(), UserID: userID, Title: title, PasswordEncrypted: password}, nil
}

func (m *mockPasswordService) GeneratePassword(ctx context.Context, clue string, masterKey string) (string, error) {
	if m.generatePasswordFn != nil {
		return m.generatePasswordFn(ctx, clue, masterKey)
	}
	return "N4s1G0r3N9#87!", nil
}

func (m *mockPasswordService) GeneratePasswordWithProfile(ctx context.Context, clue string, masterKey string, profile service.UserProfileContext) (string, error) {
	if m.generatePasswordWithProfileFn != nil {
		return m.generatePasswordWithProfileFn(ctx, clue, masterKey, profile)
	}
	return "R3nd4n9#17!", nil
}

func (m *mockPasswordService) GenerateMultiplePasswords(ctx context.Context, clue string, masterKey string, count int) ([]string, error) {
	if m.generateMultiplePasswordsFn != nil {
		return m.generateMultiplePasswordsFn(ctx, clue, masterKey, count)
	}
	return []string{"N4s1G0r3N9#87!", "n4SiG0r3nG@12!", "N@siG0r3ng$98%"}, nil
}

func (m *mockPasswordService) GenerateMultiplePasswordsWithProfile(ctx context.Context, clue string, masterKey string, profile service.UserProfileContext, count int) ([]string, error) {
	if m.generateMultiplePasswordsWithProfileFn != nil {
		return m.generateMultiplePasswordsWithProfileFn(ctx, clue, masterKey, profile, count)
	}
	return []string{"R3nd4n9#17!", "rEnD@ng@98$", "R3nd@n9$08!"}, nil
}

func (m *mockPasswordService) ValidatePassword(ctx context.Context, password string, masterKey string) (bool, error) {
	return true, nil
}

func (m *mockPasswordService) GetPassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error) {
	if m.getPasswordFn != nil {
		return m.getPasswordFn(ctx, userID, id)
	}
	return &entity.Credentials{ID: id, UserID: userID, Title: "Test"}, nil
}

func (m *mockPasswordService) GetPasswordByTitle(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error) {
	if m.getPasswordByTitleFn != nil {
		return m.getPasswordByTitleFn(ctx, userID, title)
	}
	return &entity.Credentials{ID: uuid.New(), UserID: userID, Title: title}, nil
}

func (m *mockPasswordService) GetAllPasswords(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error) {
	if m.getAllPasswordsFn != nil {
		return m.getAllPasswordsFn(ctx, userID)
	}
	return []entity.Credentials{{ID: uuid.New(), UserID: userID, Title: "Test"}}, nil
}

func (m *mockPasswordService) DeletePassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) error {
	if m.deletePasswordFn != nil {
		return m.deletePasswordFn(ctx, userID, id)
	}
	return nil
}

func TestGeneratePasswordEndpoint(t *testing.T) {
	mockSvc := &mockPasswordService{
		generateMultiplePasswordsFn: func(ctx context.Context, clue, masterKey string, count int) ([]string, error) {
			return []string{"T3stP@ssw0rd!12", "t3StP@55w0rd@34", "T3StP@ss!56"}, nil
		},
	}

	h := NewPasswordManagerHandler(mockSvc)

	body, _ := json.Marshal(GeneratePasswordRequest{
		Password: "Nasi Goreng",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.GeneratePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if success, ok := res["success"].(bool); !ok || !success {
		t.Errorf("expected success: true, got %v", res["success"])
	}

	data, ok := res["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %v", res["data"])
	}

	if pwd, ok := data["password"].(string); !ok || pwd != "Nasi Goreng" {
		t.Errorf("expected password 'Nasi Goreng', got %v", data["password"])
	}

	suggestions, ok := data["suggestions"].([]interface{})
	if !ok || len(suggestions) != 3 {
		t.Fatalf("expected 3 suggestions, got %v", data["suggestions"])
	}
}

func TestGeneratePasswordWithProfileEndpoint(t *testing.T) {
	mockSvc := &mockPasswordService{
		generateMultiplePasswordsWithProfileFn: func(ctx context.Context, clue, masterKey string, profile service.UserProfileContext, count int) ([]string, error) {
			return []string{"R3nd4n9#17!", "rEnD@ng@98$", "R3nd@n9$08!"}, nil
		},
	}

	h := NewPasswordManagerHandler(mockSvc)

	body, _ := json.Marshal(GeneratePasswordRequest{
		Password: "nasigoreng",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.GeneratePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	data, ok := res["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %v", res["data"])
	}

	suggestions, ok := data["suggestions"].([]interface{})
	if !ok || len(suggestions) != 3 {
		t.Fatalf("expected 3 suggestions, got %v", data["suggestions"])
	}
}

func TestGeneratePasswordEndpoint_MethodNotAllowed(t *testing.T) {
	h := NewPasswordManagerHandler(&mockPasswordService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/generate", nil)
	w := httptest.NewRecorder()

	h.GeneratePassword(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestGeneratePasswordEndpoint_BadRequest(t *testing.T) {
	h := NewPasswordManagerHandler(&mockPasswordService{})

	body, _ := json.Marshal(GeneratePasswordRequest{
		Password: "", // Kosong -> Bad Request
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.GeneratePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", w.Code)
	}
}

func setupTestAuth(t *testing.T) (jwtPkg.JWTService, uuid.UUID, string) {
	cfg := &config.JWTConfig{
		SecretKey:      "test-secret-key-password-handler-12345",
		ExpirationTime: 1 * time.Hour,
		Issuer:         "crypt-pass-test",
	}
	jwtService := jwtPkg.NewJWTService(cfg)
	userID := uuid.New()
	token, err := jwtService.GenerateToken(userID, "user@example.com")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return jwtService, userID, token
}

func TestCreatePasswordEndpoint(t *testing.T) {
	jwtService, userID, token := setupTestAuth(t)

	createdCredID := uuid.New()
	mockSvc := &mockPasswordService{
		createPasswordFn: func(ctx context.Context, uID uuid.UUID, title, clue, password, masterKey string) (*entity.Credentials, error) {
			if uID != userID {
				t.Errorf("expected userID %v, got %v", userID, uID)
			}
			return &entity.Credentials{
				ID:                createdCredID,
				UserID:            uID,
				Title:             title,
				PasswordEncrypted: "GeneratedSecret123!",
			}, nil
		},
	}

	h := NewPasswordManagerHandler(mockSvc)
	protectedHandler := middleware.AuthMiddleware(jwtService)(http.HandlerFunc(h.CreatePassword))

	body, _ := json.Marshal(CreatePasswordRequest{
		Title: "Google Account",
		Clue:  "SearchEngine",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	protectedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestGetPasswordsEndpoint_All(t *testing.T) {
	jwtService, userID, token := setupTestAuth(t)

	mockSvc := &mockPasswordService{
		getAllPasswordsFn: func(ctx context.Context, uID uuid.UUID) ([]entity.Credentials, error) {
			return []entity.Credentials{
				{ID: uuid.New(), UserID: uID, Title: "Item 1", PasswordEncrypted: "Secret1"},
				{ID: uuid.New(), UserID: uID, Title: "Item 2", PasswordEncrypted: "Secret2"},
			}, nil
		},
	}

	h := NewPasswordManagerHandler(mockSvc)
	protectedHandler := middleware.AuthMiddleware(jwtService)(http.HandlerFunc(h.GetPasswords))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	protectedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestDeletePasswordEndpoint(t *testing.T) {
	jwtService, userID, token := setupTestAuth(t)
	targetID := uuid.New()

	deleted := false
	mockSvc := &mockPasswordService{
		deletePasswordFn: func(ctx context.Context, uID uuid.UUID, id uuid.UUID) error {
			if uID == userID && id == targetID {
				deleted = true
				return nil
			}
			return errors.New("not found")
		},
	}

	h := NewPasswordManagerHandler(mockSvc)
	protectedHandler := middleware.AuthMiddleware(jwtService)(http.HandlerFunc(h.DeletePassword))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords?id="+targetID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	protectedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	if !deleted {
		t.Error("expected deletePasswordFn to be called with matching IDs")
	}
}
