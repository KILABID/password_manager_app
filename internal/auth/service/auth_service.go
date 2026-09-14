package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"crypt-pass/config"
	entity "crypt-pass/internal/auth/entity"
	"crypt-pass/internal/auth/repository"
	jwtPkg "crypt-pass/pkg/jwt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(ctx context.Context, name, email, password, backupSalt, birthDate, favoriteFood, dreamCity string) (*entity.User, error)
	Login(ctx context.Context, email, password string) (*entity.User, string, string, error)
	RefreshToken(ctx context.Context, rawRefreshToken string) (string, string, error)
	Logout(ctx context.Context, rawRefreshToken string) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
	RecoverAccount(ctx context.Context, email, backupSalt, birthDate, favoriteFood, dreamCity, newPassword string) error
}

type authServiceImpl struct {
	repo       repository.AuthRepository
	jwtService jwtPkg.JWTService
	jwtCfg     *config.JWTConfig
}

func NewAuthService(repo repository.AuthRepository, jwtService jwtPkg.JWTService, jwtCfg *config.JWTConfig) AuthService {
	return &authServiceImpl{
		repo:       repo,
		jwtService: jwtService,
		jwtCfg:     jwtCfg,
	}
}

func (s *authServiceImpl) Register(ctx context.Context, name, email, password, backupSalt, birthDate, favoriteFood, dreamCity string) (*entity.User, error) {
	existingUser, _ := s.repo.GetUserByEmail(ctx, email)
	if existingUser != nil {
		return nil, errors.New("email is already registered")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	if backupSalt == "" {
		generatedSalt, err := generateRandomToken(16)
		if err != nil {
			return nil, err
		}
		backupSalt = generatedSalt
	}

	user := &entity.User{
		ID:                 uuid.New(),
		Name:               name,
		Email:              email,
		MasterPasswordHash: string(hashedPassword),
		BackupSalt:         backupSalt,
		BirthDate:          birthDate,
		FavoriteFood:       favoriteFood,
		DreamCity:          dreamCity,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *authServiceImpl) Login(ctx context.Context, email, password string) (*entity.User, string, string, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, "", "", errors.New("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.MasterPasswordHash), []byte(password)); err != nil {
		return nil, "", "", errors.New("invalid email or password")
	}

	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Email)
	if err != nil {
		return nil, "", "", err
	}

	refreshToken, err := s.generateAndSaveRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, "", "", err
	}

	return user, accessToken, refreshToken, nil
}

func (s *authServiceImpl) RefreshToken(ctx context.Context, rawRefreshToken string) (string, string, error) {
	if rawRefreshToken == "" {
		return "", "", errors.New("refresh token is required")
	}

	tokenHash := hashToken(rawRefreshToken)
	storedToken, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil || storedToken == nil {
		return "", "", errors.New("invalid or expired refresh token")
	}

	if storedToken.RevokedAt != nil || time.Now().After(storedToken.ExpiresAt) {
		return "", "", errors.New("invalid or expired refresh token")
	}

	// Revoke old refresh token (Token Rotation)
	_ = s.repo.RevokeRefreshToken(ctx, storedToken.ID)

	// Generate new access token
	newAccessToken, err := s.jwtService.GenerateToken(storedToken.UserID, storedToken.User.Email)
	if err != nil {
		return "", "", err
	}

	// Generate new refresh token
	newRefreshToken, err := s.generateAndSaveRefreshToken(ctx, storedToken.UserID)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func (s *authServiceImpl) Logout(ctx context.Context, rawRefreshToken string) error {
	if rawRefreshToken == "" {
		return errors.New("refresh token is required")
	}

	tokenHash := hashToken(rawRefreshToken)
	storedToken, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil || storedToken == nil {
		return nil // idempotent logout
	}

	return s.repo.RevokeRefreshToken(ctx, storedToken.ID)
}

func (s *authServiceImpl) GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	return s.repo.GetUserByID(ctx, id)
}

func (s *authServiceImpl) RecoverAccount(ctx context.Context, email, backupSalt, birthDate, favoriteFood, dreamCity, newPassword string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return errors.New("invalid recovery credentials or profile answers")
	}

	// Verifikasi backup_salt dan jawaban pertanyaan keamanan profil
	if user.BackupSalt != backupSalt ||
		user.BirthDate != birthDate ||
		!strings.EqualFold(strings.TrimSpace(user.FavoriteFood), strings.TrimSpace(favoriteFood)) ||
		!strings.EqualFold(strings.TrimSpace(user.DreamCity), strings.TrimSpace(dreamCity)) {
		return errors.New("invalid recovery credentials or profile answers")
	}

	// Hash password master baru
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.MasterPasswordHash = string(hashedPassword)

	// Cabut seluruh sesi refresh token aktif demi keamanan
	_ = s.repo.RevokeAllUserRefreshTokens(ctx, user.ID)

	return s.repo.UpdateUser(ctx, user)
}

func (s *authServiceImpl) generateAndSaveRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	rawToken, err := generateRandomToken(32)
	if err != nil {
		return "", err
	}

	tokenHash := hashToken(rawToken)
	expiresAt := time.Now().Add(s.jwtCfg.RefreshTokenExpiration)

	refreshToken := &entity.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.repo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return "", err
	}

	return rawToken, nil
}

func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}


