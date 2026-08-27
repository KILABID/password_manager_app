package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"crypt-pass/config"
	"crypt-pass/internal/auth/handler"
	"crypt-pass/internal/auth/repository"
	"crypt-pass/internal/auth/service"
	"crypt-pass/internal/infrastructure"
)

func main() {
	cfg := config.LoadDBConfig()

	db, err := infrastructure.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	authRepo := repository.NewAuthRepository(db)
	authService := service.NewAuthService(authRepo)
	authHandler := handler.NewAuthHandler(authService)

	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("/api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server running on port :%s...\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
