package main

import (
	"context"
	"fmt"
	"log"

	"crypt-pass/config"
	authEntity "crypt-pass/internal/auth/entity"
	infrastructure "crypt-pass/internal/infrastructure"
	pmEntity "crypt-pass/internal/password_manager/entity"
	"crypt-pass/migration"
	cryptoPkg "crypt-pass/pkg/crypto"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("  Crypt-Pass: Multi-Database Migration & Seeder  ")
	fmt.Println("==================================================")

	// 1. Load Configurations
	authDBCfg := config.LoadDBConfig()
	vaultDBCfg := config.LoadVaultDBConfig()
	vaultSecret := config.LoadEncryptionSecret()

	// 2. Connect to Auth Database
	authDB, err := infrastructure.Connect(authDBCfg)
	if err != nil {
		log.Fatalf("[Auth DB] Failed to connect: %v", err)
	}
	fmt.Printf("[Auth DB] Connected to '%s' at %s:%s\n", authDBCfg.DBName, authDBCfg.DBHost, authDBCfg.DBPort)

	// 3. Connect to Vault Database (Separate or Shared)
	vaultDB := authDB
	if vaultDBCfg.DBHost != authDBCfg.DBHost || vaultDBCfg.DBPort != authDBCfg.DBPort || vaultDBCfg.DBName != authDBCfg.DBName {
		vaultDB, err = infrastructure.Connect(vaultDBCfg)
		if err != nil {
			log.Fatalf("[Vault DB] Failed to connect: %v", err)
		}
		fmt.Printf("[Vault DB] Connected to dedicated database '%s' at %s:%s\n", vaultDBCfg.DBName, vaultDBCfg.DBHost, vaultDBCfg.DBPort)
	} else {
		fmt.Printf("[Vault DB] Using shared database '%s'\n", authDBCfg.DBName)
	}

	// 4. Run Migrations on Auth DB
	fmt.Println("\n--- Running Migrations on Auth DB ---")
	authModels := []interface{}{
		&authEntity.User{},
		&authEntity.RefreshToken{},
	}
	if err := migration.Migrate(authDB, authModels...); err != nil {
		log.Fatalf("[Auth DB] Migration failed: %v", err)
	}
	fmt.Println("[Auth DB] Migrated tables: users, refresh_tokens")

	// 5. Run Migrations on Vault DB
	fmt.Println("\n--- Running Migrations on Vault DB ---")
	vaultModels := []interface{}{
		&pmEntity.Credentials{},
	}
	if err := migration.Migrate(vaultDB, vaultModels...); err != nil {
		log.Fatalf("[Vault DB] Migration failed: %v", err)
	}
	fmt.Println("[Vault DB] Migrated tables: credentials")

	// 6. Seed Demo User in Auth DB
	fmt.Println("\n--- Seeding Demo User (Auth DB) ---")
	demoEmail := "testuser@cryptpass.com"
	var user authEntity.User
	result := authDB.WithContext(context.Background()).Where("email = ?", demoEmail).First(&user)

	if result.Error != nil {
		// User belum ada, buat baru
		rawPassword := "MasterPassword123!"
		hashedPass, err := bcrypt.GenerateFromPassword([]byte(rawPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("failed to hash password: %v", err)
		}

		user = authEntity.User{
			ID:                 uuid.New(),
			Name:               "Aldi Murad",
			Email:              demoEmail,
			MasterPasswordHash: string(hashedPass),
			BackupSalt:         "demo-salt-vault-1998-secret",
			BirthDate:          "1998-08-17",
			FavoriteFood:       "Rendang",
			DreamCity:          "Tokyo",
		}

		if err := authDB.Create(&user).Error; err != nil {
			log.Fatalf("[Auth DB] Failed to seed user: %v", err)
		}
		fmt.Printf("[Auth DB] Created demo user: %s (Email: %s)\n", user.Name, user.Email)
		fmt.Printf("          Password Login: %s\n", rawPassword)
	} else {
		fmt.Printf("[Auth DB] Demo user already exists: %s (ID: %s)\n", user.Email, user.ID)
	}

	// 7. Seed Encrypted Credentials in Vault DB
	fmt.Println("\n--- Seeding Encrypted Credentials (Vault DB) ---")
	userEncryptionKey := cryptoPkg.DeriveKey(vaultSecret, user.BackupSalt)

	seedItems := []struct {
		Title         string
		Clue          string
		PlainPassword string
	}{
		{
			Title:         "Google Account",
			Clue:          "Google",
			PlainPassword: "G00gl3@17!",
		},
		{
			Title:         "GitHub Developer",
			Clue:          "Rendang",
			PlainPassword: "R3nd4n9#98$",
		},
		{
			Title:         "AWS Cloud Console",
			Clue:          "Tokyo",
			PlainPassword: "T0ky0+1998*",
		},
	}

	for _, item := range seedItems {
		var existing pmEntity.Credentials
		findErr := vaultDB.WithContext(context.Background()).
			Where("user_id = ? AND title = ? AND is_deleted = false", user.ID, item.Title).
			First(&existing).Error

		if findErr == nil {
			fmt.Printf("[Vault DB] Item '%s' already exists (ID: %s)\n", item.Title, existing.ID)
			continue
		}

		encryptedPassword, err := cryptoPkg.EncryptAES256GCM(item.PlainPassword, userEncryptionKey)
		if err != nil {
			log.Fatalf("failed to encrypt password for '%s': %v", item.Title, err)
		}

		cred := pmEntity.Credentials{
			ID:                uuid.New(),
			UserID:            user.ID,
			Title:             item.Title,
			Clue:              item.Clue,
			PasswordEncrypted: encryptedPassword,
			IsDeleted:         false,
			IsDirty:           false,
		}

		if err := vaultDB.Create(&cred).Error; err != nil {
			log.Fatalf("[Vault DB] Failed to insert credential '%s': %v", item.Title, err)
		}

		fmt.Printf("[Vault DB] Seeded Credential: '%s'\n", item.Title)
		fmt.Printf("           Plaintext  : %s\n", item.PlainPassword)
		fmt.Printf("           Encrypted  : %s\n", encryptedPassword)
	}

	fmt.Println("\n==================================================")
	fmt.Println("  Migration & Vault Seeding Completed Successfully!  ")
	fmt.Println("==================================================")
}
