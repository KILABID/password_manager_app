package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type JWTConfig struct {
	SecretKey             string
	ExpirationTime        time.Duration
	AccessTokenExpiration time.Duration
	RefreshTokenExpiration time.Duration
	Issuer                string
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

	// Access token expiration: defaults to 15 minutes, or fallback to JWT_EXPIRATION_HOURS if set
	accessExp := 15 * time.Minute
	if accessMinStr := os.Getenv("JWT_ACCESS_EXPIRATION_MINUTES"); accessMinStr != "" {
		if val, err := strconv.Atoi(accessMinStr); err == nil && val > 0 {
			accessExp = time.Duration(val) * time.Minute
		}
	} else if expHoursStr := os.Getenv("JWT_EXPIRATION_HOURS"); expHoursStr != "" {
		if val, err := strconv.Atoi(expHoursStr); err == nil && val > 0 {
			accessExp = time.Duration(val) * time.Hour
		}
	}

	// Refresh token expiration: defaults to 30 days
	refreshDays := 30
	if refreshDaysStr := os.Getenv("JWT_REFRESH_EXPIRATION_DAYS"); refreshDaysStr != "" {
		if val, err := strconv.Atoi(refreshDaysStr); err == nil && val > 0 {
			refreshDays = val
		}
	}
	refreshExp := time.Duration(refreshDays) * 24 * time.Hour

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "crypt-pass"
	}

	return &JWTConfig{
		SecretKey:              secret,
		ExpirationTime:         accessExp,
		AccessTokenExpiration:  accessExp,
		RefreshTokenExpiration: refreshExp,
		Issuer:                 issuer,
	}
}
