package main

import (
	"crypt-pass/config"
	authEntity "crypt-pass/internal/auth/entity"
	infrastructure "crypt-pass/internal/infrastructure"
	pmEntity "crypt-pass/internal/password_manager/entity"
	"crypt-pass/migration"
	"fmt"
	"log"
)

var models = []interface{}{
	&authEntity.User{},
	&pmEntity.Credentials{},
}

func main() {
	cfg := config.LoadDBConfig()

	db, err := infrastructure.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to get sql.DB from gorm: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		fmt.Println("database disconnected")
		return
	}
	fmt.Println("Database connected!")
	defer sqlDB.Close()

	// Run auto migrations for development
	if err := migration.Migrate(db, models...); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
	fmt.Println("Migrations completed")
}
