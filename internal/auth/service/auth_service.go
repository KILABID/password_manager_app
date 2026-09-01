package service

import (
	"context"
	"errors"

	entity "crypt-pass/internal/auth/entity"
	"crypt-pass/internal/auth/repository"
	jwtPkg "crypt-pass/pkg/jwt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(ctx context.Context, name, email, password, backupSalt string) (*entity.User, error)
	Login(ctx context.Context, email, password string) (*entity.User, string, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
}

type authServiceImpl struct {
	repo       repository.AuthRepository
	jwtService jwtPkg.JWTService
}

func NewAuthService(repo repository.AuthRepository, jwtService jwtPkg.JWTService) AuthService {
	return &authServiceImpl{
		repo:       repo,
		jwtService: jwtService,
	}
}

func (s *authServiceImpl) Register(ctx context.Context, name, email, password, backupSalt string) (*entity.User, error) {
	existingUser, _ := s.repo.GetUserByEmail(ctx, email)
	if existingUser != nil {
		return nil, errors.New("email is already registered")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &entity.User{
		ID:                 uuid.New(),
		Name:               name,
		Email:              email,
		MasterPasswordHash: string(hashedPassword),
		BackupSalt:         backupSalt,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *authServiceImpl) Login(ctx context.Context, email, password string) (*entity.User, string, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, "", errors.New("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.MasterPasswordHash), []byte(password)); err != nil {
		return nil, "", errors.New("invalid email or password")
	}

	token, err := s.jwtService.GenerateToken(user.ID, user.Email)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *authServiceImpl) GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	return s.repo.GetUserByID(ctx, id)
}

