package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"crypt-pass/config"
	entity "crypt-pass/internal/auth/entity"
	"crypt-pass/internal/auth/service"
	jwtPkg "crypt-pass/pkg/jwt"

	"github.com/google/uuid"
)

// MockAuthRepository is an in-memory repository for unit testing
type MockAuthRepository struct {
	users         map[string]*entity.User
	refreshTokens map[string]*entity.RefreshToken
}

func NewMockAuthRepository() *MockAuthRepository {
	return &MockAuthRepository{
		users:         make(map[string]*entity.User),
		refreshTokens: make(map[string]*entity.RefreshToken),
	}
}

func (m *MockAuthRepository) CreateUser(ctx context.Context, user *entity.User) error {
	m.users[user.Email] = user
	return nil
}

func (m *MockAuthRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, errors.New("user not found")
}

func (m *MockAuthRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	u, ok := m.users[email]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (m *MockAuthRepository) UpdateUser(ctx context.Context, user *entity.User) error {
	m.users[user.Email] = user
	return nil
}

func (m *MockAuthRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	for email, u := range m.users {
		if u.ID == id {
			delete(m.users, email)
			return nil
		}
	}
	return nil
}

func (m *MockAuthRepository) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	m.refreshTokens[token.TokenHash] = token
	return nil
}

func (m *MockAuthRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	t, ok := m.refreshTokens[tokenHash]
	if !ok {
		return nil, errors.New("token not found")
	}
	// Attach user
	for _, u := range m.users {
		if u.ID == t.UserID {
			t.User = *u
			break
		}
	}
	return t, nil
}

func (m *MockAuthRepository) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	for _, t := range m.refreshTokens {
		if t.ID == id && t.RevokedAt == nil {
			t.RevokedAt = &now
			return nil
		}
	}
	return nil
}

func (m *MockAuthRepository) RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	for _, t := range m.refreshTokens {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func setupTestAuthService() (service.AuthService, *MockAuthRepository, jwtPkg.JWTService) {
	cfg := &config.JWTConfig{
		SecretKey:              "test-jwt-secret-key-1234567890123456",
		ExpirationTime:         15 * time.Minute,
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		Issuer:                 "crypt-pass-test",
	}

	repo := NewMockAuthRepository()
	jwtSvc := jwtPkg.NewJWTService(cfg)
	authSvc := service.NewAuthService(repo, jwtSvc, cfg)
	return authSvc, repo, jwtSvc
}

func TestAuthService_RegisterAndLogin(t *testing.T) {
	authSvc, _, _ := setupTestAuthService()
	ctx := context.Background()

	// Register
	user, err := authSvc.Register(ctx, "John Doe", "john@example.com", "MasterPass123!", "salt123")
	if err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}
	if user.Email != "john@example.com" {
		t.Errorf("expected email john@example.com, got %s", user.Email)
	}

	// Login
	loggedInUser, accessToken, refreshToken, err := authSvc.Login(ctx, "john@example.com", "MasterPass123!")
	if err != nil {
		t.Fatalf("unexpected login error: %v", err)
	}
	if loggedInUser.ID != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, loggedInUser.ID)
	}
	if accessToken == "" {
		t.Error("expected non-empty access token")
	}
	if refreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
}

func TestAuthService_RefreshToken_SuccessAndRotation(t *testing.T) {
	authSvc, repo, jwtSvc := setupTestAuthService()
	ctx := context.Background()

	_, _ = authSvc.Register(ctx, "Alice", "alice@example.com", "SecretPass123!", "salt456")
	_, _, oldRefresh, err := authSvc.Login(ctx, "alice@example.com", "SecretPass123!")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Perform refresh
	newAccess, newRefresh, err := authSvc.RefreshToken(ctx, oldRefresh)
	if err != nil {
		t.Fatalf("refresh token failed: %v", err)
	}

	if newAccess == "" || newRefresh == "" {
		t.Fatal("expected non-empty new access and refresh tokens")
	}
	if newRefresh == oldRefresh {
		t.Error("expected new refresh token to differ from old refresh token (token rotation)")
	}

	// Validate new access token
	claims, err := jwtSvc.ValidateToken(newAccess)
	if err != nil {
		t.Fatalf("failed to validate new access token: %v", err)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", claims.Email)
	}

	// Verify old refresh token is revoked in repo
	oldHash := sha256.Sum256([]byte(oldRefresh))
	storedOldToken, err := repo.GetRefreshTokenByHash(ctx, hex.EncodeToString(oldHash[:]))
	if err != nil {
		t.Fatalf("failed to retrieve old token: %v", err)
	}
	if storedOldToken.RevokedAt == nil {
		t.Error("expected old refresh token to have RevokedAt set")
	}

	// Attempting to reuse old refresh token should now fail
	_, _, err = authSvc.RefreshToken(ctx, oldRefresh)
	if err == nil {
		t.Error("expected error when using revoked refresh token, got nil")
	}
}

func TestAuthService_Logout(t *testing.T) {
	authSvc, _, _ := setupTestAuthService()
	ctx := context.Background()

	_, _ = authSvc.Register(ctx, "Bob", "bob@example.com", "BobPass123!", "salt789")
	_, _, refreshToken, err := authSvc.Login(ctx, "bob@example.com", "BobPass123!")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Logout
	if err := authSvc.Logout(ctx, refreshToken); err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	// Refresh after logout should fail
	_, _, err = authSvc.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Error("expected refresh after logout to fail, got nil")
	}
}
