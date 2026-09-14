package repository

import (
	"context"
	"time"

	entity "crypt-pass/internal/auth/entity"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthRepository interface {
	CreateUser(ctx context.Context, user *entity.User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
	UpdateUser(ctx context.Context, user *entity.User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// Refresh Token methods
	CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id uuid.UUID) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error
}

type AuthRepositoryImpl struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &AuthRepositoryImpl{db: db}
}

func (r *AuthRepositoryImpl) CreateUser(ctx context.Context, user *entity.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *AuthRepositoryImpl) GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).First(&user, "email = ?", email).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) UpdateUser(ctx context.Context, user *entity.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *AuthRepositoryImpl) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&entity.User{}, "id = ?", id).Error
}

func (r *AuthRepositoryImpl) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *AuthRepositoryImpl) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	var token entity.RefreshToken
	if err := r.db.WithContext(ctx).Preload("User").First(&token, "token_hash = ?", tokenHash).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *AuthRepositoryImpl) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&entity.RefreshToken{}).Where("id = ? AND revoked_at IS NULL", id).Update("revoked_at", &now).Error
}

func (r *AuthRepositoryImpl) RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&entity.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", &now).Error
}
