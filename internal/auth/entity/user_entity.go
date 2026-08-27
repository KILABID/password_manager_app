package auth

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                 uuid.UUID `gorm:"primaryKey"`
	Name               string    `gorm:"size:100;not null"`
	Email              string    `gorm:"size:100;unique;not null"`
	MasterPasswordHash string    `gorm:"size:255;not null"`
	BackupSalt         string    `gorm:"size:64;not null"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
}
