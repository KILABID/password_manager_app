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
	DBHost: 		os.Getenv("DB_HOST"),
	DBPort: 		os.Getenv("DB_PORT"),
	DBUser: 		os.Getenv("DB_USER"),
	DBPassword: os.Getenv("DB_PASSWORD"),
	DBName: 		os.Getenv("DB_NAME"),
	DBSSLMode: 	os.Getenv("DB_SSLMODE"),
	}
}