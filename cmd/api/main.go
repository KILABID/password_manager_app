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
	"crypt-pass/pkg/middleware"
)

func main() {
	cfg := config.LoadDBConfig()

	db, err := infrastructure.Connect(cfg)
	if err != nil {
		slog.Error("Failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}

	authRepo := repository.NewAuthRepository(db)
	authService := service.NewAuthService(authRepo)
	authHandler := handler.NewAuthHandler(authService)

	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("/api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)

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

