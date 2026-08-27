package password_manager

import (
	"time"

	auth "crypt-pass/internal/auth/entity"

	"github.com/google/uuid"
)

type Credentials struct {
	ID                uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID            uuid.UUID `gorm:"type:uuid;not null;index"` // Foreign Key ke User
	User              auth.User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Title             string    `gorm:"size:100;not null"`
	PasswordEncrypted string    `gorm:"not null"`
	IsDeleted         bool      `gorm:"default:false"`
	IsDirty           bool      `gorm:"default:false"`
	CreatedAt         time.Time `gorm:"autoCreateTime"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime"`
}
