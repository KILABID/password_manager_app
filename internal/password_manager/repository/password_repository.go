package password_manager

import (
	"context"

	entity "crypt-pass/internal/password_manager/entity"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PasswordRepository interface {
	Create(ctx context.Context, cred *entity.Credentials) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Credentials, error)
	GetByUserIDAndID(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error)
	GetByUserIDAndTitle(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error)
	Update(ctx context.Context, cred *entity.Credentials) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, userID uuid.UUID, id uuid.UUID) error
}

type PasswordRepositoryImpl struct {
	db *gorm.DB
}

func NewPasswordRepository(db *gorm.DB) PasswordRepository {
	return &PasswordRepositoryImpl{db: db}
}

func (r *PasswordRepositoryImpl) Create(ctx context.Context, cred *entity.Credentials) error {
	return r.db.WithContext(ctx).Create(cred).Error
}

func (r *PasswordRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.Credentials, error) {
	var cred entity.Credentials
	if err := r.db.WithContext(ctx).First(&cred, "id = ? AND is_deleted = false", id).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *PasswordRepositoryImpl) GetByUserIDAndID(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error) {
	var cred entity.Credentials
	if err := r.db.WithContext(ctx).First(&cred, "id = ? AND user_id = ? AND is_deleted = false", id, userID).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *PasswordRepositoryImpl) GetByUserIDAndTitle(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error) {
	var cred entity.Credentials
	if err := r.db.WithContext(ctx).First(&cred, "user_id = ? AND title = ? AND is_deleted = false", userID, title).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *PasswordRepositoryImpl) GetByUserID(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error) {
	var creds []entity.Credentials
	if err := r.db.WithContext(ctx).Find(&creds, "user_id = ? AND is_deleted = false", userID).Error; err != nil {
		return nil, err
	}
	return creds, nil
}

func (r *PasswordRepositoryImpl) Update(ctx context.Context, cred *entity.Credentials) error {
	return r.db.WithContext(ctx).Save(cred).Error
}

func (r *PasswordRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&entity.Credentials{}).Where("id = ?", id).Update("is_deleted", true).Error
}

func (r *PasswordRepositoryImpl) SoftDelete(ctx context.Context, userID uuid.UUID, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&entity.Credentials{}).Where("id = ? AND user_id = ? AND is_deleted = false", id, userID).Update("is_deleted", true)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
