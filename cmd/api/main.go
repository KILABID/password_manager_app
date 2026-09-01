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
	"crypt-pass/pkg/jwt"
	"crypt-pass/pkg/middleware"
)

func main() {
	dbCfg := config.LoadDBConfig()
	jwtCfg := config.LoadJWTConfig()

	db, err := infrastructure.Connect(dbCfg)
	if err != nil {
		slog.Error("Failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}

	jwtService := jwt.NewJWTService(jwtCfg)
	authRepo := repository.NewAuthRepository(db)
	authService := service.NewAuthService(authRepo, jwtService)
	authHandler := handler.NewAuthHandler(authService)

	authMiddleware := middleware.AuthMiddleware(jwtService)

	mux := http.NewServeMux()

	// Public auth routes
	mux.HandleFunc("/api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)

	// Protected routes (require valid JWT)
	mux.Handle("/api/v1/auth/me", authMiddleware(http.HandlerFunc(authHandler.GetProfile)))

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


