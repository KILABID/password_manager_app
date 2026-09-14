package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type DBConfig struct{
	DBHost			string
	DBPort 			string
	DBUser			string
	DBPassword	string
	DBName			string
	DBSSLMode		string
}

func LoadDBConfig() *DBConfig {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env file not found, using system environment")
	}

	return &DBConfig{
		DBHost:     os.Getenv("DB_HOST"),
		DBPort:     os.Getenv("DB_PORT"),
		DBUser:     os.Getenv("DB_USER"),
		DBPassword: os.Getenv("DB_PASSWORD"),
		DBName:     os.Getenv("DB_NAME"),
		DBSSLMode:  os.Getenv("DB_SSLMODE"),
	}
}

// LoadVaultDBConfig memuat konfigurasi database terpisah untuk Vault/Credentials.
// Jika variabel VAULT_DB_* tidak diset, otomatis fallback ke konfigurasi DB utama.
func LoadVaultDBConfig() *DBConfig {
	_ = godotenv.Load()

	vaultHost := os.Getenv("VAULT_DB_HOST")
	if vaultHost == "" {
		return LoadDBConfig()
	}

	return &DBConfig{
		DBHost:     vaultHost,
		DBPort:     os.Getenv("VAULT_DB_PORT"),
		DBUser:     os.Getenv("VAULT_DB_USER"),
		DBPassword: os.Getenv("VAULT_DB_PASSWORD"),
		DBName:     os.Getenv("VAULT_DB_NAME"),
		DBSSLMode:  os.Getenv("VAULT_DB_SSLMODE"),
	}
}

// LoadEncryptionSecret memuat secret key untuk enkripsi AES-256 Vault
func LoadEncryptionSecret() string {
	_ = godotenv.Load()
	secret := os.Getenv("VAULT_ENCRYPTION_KEY")
	if secret == "" {
		secret = os.Getenv("JWT_SECRET")
	}
	if secret == "" {
		secret = "crypt-pass-default-32-byte-secret-key!"
	}
	return secret
}