package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type JWTConfig struct {
	SecretKey      string
	ExpirationTime time.Duration
	Issuer         string
}

func LoadJWTConfig() *JWTConfig {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found, using system environment")
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "default_secret_key_change_me_in_production"
	}

	expHoursStr := os.Getenv("JWT_EXPIRATION_HOURS")
	expHours := 24 // default 24 hours
	if expHoursStr != "" {
		if val, err := strconv.Atoi(expHoursStr); err == nil && val > 0 {
			expHours = val
		}
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "crypt-pass"
	}

	return &JWTConfig{
		SecretKey:      secret,
		ExpirationTime: time.Duration(expHours) * time.Hour,
		Issuer:         issuer,
	}
}
