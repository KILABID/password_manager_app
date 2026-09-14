package main

import (
	"log/slog"
	"net/http"
	"os"

	"crypt-pass/config"
	"crypt-pass/internal/auth/handler"
	"crypt-pass/internal/auth/repository"
	"crypt-pass/internal/auth/service"
	"crypt-pass/internal/infrastructure"
	pmHandler "crypt-pass/internal/password_manager/handler"
	pmRepository "crypt-pass/internal/password_manager/repository"
	pmService "crypt-pass/internal/password_manager/service"
	"crypt-pass/pkg/jwt"
	"crypt-pass/pkg/middleware"
)

func main() {
	dbCfg := config.LoadDBConfig()
	vaultDBCfg := config.LoadVaultDBConfig()
	jwtCfg := config.LoadJWTConfig()
	vaultSecret := config.LoadEncryptionSecret()

	authDB, err := infrastructure.Connect(dbCfg)
	if err != nil {
		slog.Error("Failed to connect to auth database", slog.String("error", err.Error()))
		os.Exit(1)
	}

	var vaultDB = authDB
	// Jika konfigurasi host/port/dbname vault berbeda dengan auth DB, buka koneksi terpisah
	if vaultDBCfg.DBHost != dbCfg.DBHost || vaultDBCfg.DBPort != dbCfg.DBPort || vaultDBCfg.DBName != dbCfg.DBName {
		vaultDB, err = infrastructure.Connect(vaultDBCfg)
		if err != nil {
			slog.Error("Failed to connect to separate vault database", slog.String("error", err.Error()))
			os.Exit(1)
		}
		slog.Info("Connected to dedicated Vault database", slog.String("vault_db", vaultDBCfg.DBName))
	} else {
		slog.Info("Using shared database connection for Auth and Vault")
	}

	jwtService := jwt.NewJWTService(jwtCfg)
	authRepo := repository.NewAuthRepository(authDB)
	authService := service.NewAuthService(authRepo, jwtService, jwtCfg)
	authHandler := handler.NewAuthHandler(authService)

	pmRepo := pmRepository.NewPasswordRepository(vaultDB)
	pmServiceInstance := pmService.NewPasswordManagerService(pmRepo, authRepo, vaultSecret)
	pmHandlerInstance := pmHandler.NewPasswordManagerHandler(pmServiceInstance)

	authMiddleware := middleware.AuthMiddleware(jwtService)

	mux := http.NewServeMux()

	// Public auth routes
	mux.HandleFunc("/api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("/api/v1/auth/refresh", authHandler.RefreshToken)
	mux.HandleFunc("/api/v1/auth/logout", authHandler.Logout)
	mux.HandleFunc("/api/v1/auth/recover", authHandler.RecoverAccount)

	// Protected auth routes (require valid JWT)
	mux.Handle("/api/v1/auth/me", authMiddleware(http.HandlerFunc(authHandler.GetProfile)))

	// Password routes (Protected)
	mux.Handle("/api/v1/passwords/generate", authMiddleware(http.HandlerFunc(pmHandlerInstance.GeneratePassword)))
	mux.Handle("/api/v1/passwords", authMiddleware(http.HandlerFunc(pmHandlerInstance.HandlePasswords)))
	mux.Handle("/api/v1/passwords/", authMiddleware(http.HandlerFunc(pmHandlerInstance.HandlePasswords)))

	// Wrap router with Logger middleware
	handlerWithMiddleware := middleware.Logger(mux)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	slog.Info("Server running", slog.String("port", port))
	if err := http.ListenAndServe(":"+port, handlerWithMiddleware); err != nil {
		slog.Error("Server failed to start", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
