package password_manager

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"unicode"

	authRepo "crypt-pass/internal/auth/repository"
	entity "crypt-pass/internal/password_manager/entity"
	repository "crypt-pass/internal/password_manager/repository"
	cryptoPkg "crypt-pass/pkg/crypto"
	"crypt-pass/pkg/middleware"

	"github.com/google/uuid"
)

type UserProfileContext struct {
	BirthDate    string `json:"birth_date"`
	FavoriteFood string `json:"favorite_food"`
	DreamCity    string `json:"dream_city"`
}

type PasswordManagerService interface {
	CreatePassword(ctx context.Context, userID uuid.UUID, title, clue, password, masterKey string) (*entity.Credentials, error)
	GeneratePassword(ctx context.Context, clue string, masterKey string) (string, error)
	GeneratePasswordWithProfile(ctx context.Context, clue string, masterKey string, profile UserProfileContext) (string, error)
	GenerateMultiplePasswords(ctx context.Context, clue string, masterKey string, count int) ([]string, error)
	GenerateMultiplePasswordsWithProfile(ctx context.Context, clue string, masterKey string, profile UserProfileContext, count int) ([]string, error)
	ValidatePassword(ctx context.Context, password string, masterKey string) (bool, error)
	GetPassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error)
	GetPasswordByTitle(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error)
	GetAllPasswords(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error)
	DeletePassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) error
}

type passwordManagerServiceImpl struct {
	repo        repository.PasswordRepository
	authRepo    authRepo.AuthRepository
	vaultSecret string
}

func NewPasswordManagerService(repo repository.PasswordRepository, authRepo authRepo.AuthRepository, vaultSecret string) PasswordManagerService {
	if vaultSecret == "" {
		vaultSecret = "crypt-pass-default-32-byte-secret-key!"
	}
	return &passwordManagerServiceImpl{
		repo:        repo,
		authRepo:    authRepo,
		vaultSecret: vaultSecret,
	}
}

func (s *passwordManagerServiceImpl) getUserKey(ctx context.Context, userID uuid.UUID) []byte {
	salt := userID.String()
	if s.authRepo != nil {
		user, err := s.authRepo.GetUserByID(ctx, userID)
		if err == nil && user != nil && user.BackupSalt != "" {
			salt = user.BackupSalt
		}
	}
	return cryptoPkg.DeriveKey(s.vaultSecret, salt)
}

func (s *passwordManagerServiceImpl) CreatePassword(ctx context.Context, userID uuid.UUID, title, clue, password, masterKey string) (*entity.Credentials, error) {
	finalPassword := password

	// Jika password belum terisi, fallback mengenerate dari clue / profil user
	if finalPassword == "" {
		var birthDate, favoriteFood, dreamCity string
		if s.authRepo != nil {
			user, err := s.authRepo.GetUserByID(ctx, userID)
			if err == nil && user != nil {
				birthDate = user.BirthDate
				favoriteFood = user.FavoriteFood
				dreamCity = user.DreamCity
			}
		}

		baseInput := clue
		if baseInput == "" {
			baseInput = title
		}
		finalPassword = GeneratePasswordWithProfile(baseInput, masterKey, birthDate, favoriteFood, dreamCity)
	}

	// Enkripsi password pilihan user menggunakan AES-256-GCM
	key := s.getUserKey(ctx, userID)
	encryptedPassword, err := cryptoPkg.EncryptAES256GCM(finalPassword, key)
	if err != nil {
		return nil, err
	}

	// Simpan ke database Vault dalam keadaan terenkripsi
	cred := &entity.Credentials{
		ID:                uuid.New(),
		UserID:            userID,
		Title:             title,
		Clue:              clue,
		PasswordEncrypted: encryptedPassword,
		IsDeleted:         false,
		IsDirty:           false,
	}
	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, err
	}

	// Buat salinan untuk dikembalikan ke caller dengan password plaintext
	resultCred := *cred
	resultCred.PasswordEncrypted = finalPassword
	return &resultCred, nil
}

func (s *passwordManagerServiceImpl) GeneratePassword(ctx context.Context, clue string, masterKey string) (string, error) {
	generated := GeneratePassword(clue, masterKey)
	return generated, nil
}

func (s *passwordManagerServiceImpl) GeneratePasswordWithProfile(ctx context.Context, clue string, masterKey string, profile UserProfileContext) (string, error) {
	generated := GeneratePasswordWithProfile(clue, masterKey, profile.BirthDate, profile.FavoriteFood, profile.DreamCity)
	return generated, nil
}

func (s *passwordManagerServiceImpl) GenerateMultiplePasswords(ctx context.Context, clue string, masterKey string, count int) ([]string, error) {
	var birthDate, favoriteFood, dreamCity string
	if s.authRepo != nil {
		if userID, ok := middleware.GetUserID(ctx); ok {
			if user, err := s.authRepo.GetUserByID(ctx, userID); err == nil && user != nil {
				birthDate = user.BirthDate
				favoriteFood = user.FavoriteFood
				dreamCity = user.DreamCity
			}
		}
	}
	return GenerateMultiplePasswordsWithProfile(clue, masterKey, birthDate, favoriteFood, dreamCity, count), nil
}

func (s *passwordManagerServiceImpl) GenerateMultiplePasswordsWithProfile(ctx context.Context, clue string, masterKey string, profile UserProfileContext, count int) ([]string, error) {
	return GenerateMultiplePasswordsWithProfile(clue, masterKey, profile.BirthDate, profile.FavoriteFood, profile.DreamCity, count), nil
}

func (s *passwordManagerServiceImpl) ValidatePassword(ctx context.Context, password string, masterKey string) (bool, error) {
	if password == "" {
		return false, errors.New("password cannot be empty")
	}
	return true, nil
}

func (s *passwordManagerServiceImpl) GetPassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error) {
	cred, err := s.repo.GetByUserIDAndID(ctx, userID, id)
	if err != nil || cred == nil {
		return nil, err
	}

	key := s.getUserKey(ctx, userID)
	if decrypted, decErr := cryptoPkg.DecryptAES256GCM(cred.PasswordEncrypted, key); decErr == nil {
		cred.PasswordEncrypted = decrypted
	}
	return cred, nil
}

func (s *passwordManagerServiceImpl) GetPasswordByTitle(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error) {
	cred, err := s.repo.GetByUserIDAndTitle(ctx, userID, title)
	if err != nil || cred == nil {
		return nil, err
	}

	key := s.getUserKey(ctx, userID)
	if decrypted, decErr := cryptoPkg.DecryptAES256GCM(cred.PasswordEncrypted, key); decErr == nil {
		cred.PasswordEncrypted = decrypted
	}
	return cred, nil
}

func (s *passwordManagerServiceImpl) GetAllPasswords(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error) {
	creds, err := s.repo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Jangan dekripsi password pada list view demi keamanan (zero-leak) dan efisiensi memori.
	// Password hanya didekripsi saat pemanggilan detail (GetPassword by ID / Title).
	for i := range creds {
		creds[i].PasswordEncrypted = ""
	}
	return creds, nil
}

func (s *passwordManagerServiceImpl) DeletePassword(ctx context.Context, userID uuid.UUID, id uuid.UUID) error {
	return s.repo.SoftDelete(ctx, userID, id)
}

var leetMap = map[rune][]rune{
	'a': {'4', '@', 'A', 'a'},
	'b': {'8', 'B', 'b'},
	'c': {'(', '<', 'C', 'c'},
	'e': {'3', 'E', 'e'},
	'g': {'9', '6', 'G', 'g'},
	'i': {'1', '!', 'I', 'i'},
	'l': {'1', '|', 'L', 'l'},
	'o': {'0', 'O', 'o'},
	's': {'5', '$', 'S', 's'},
	't': {'7', '+', 'T', 't'},
	'z': {'2', 'Z', 'z'},
}

const (
	specialSymbols = "!@#$%^&*-_+=?"
	digitChars     = "0123456789"
)

// GeneratePassword menghasilkan password default jika profile data tidak tersedia
func GeneratePassword(clue string, masterKey string) string {
	return GeneratePasswordWithProfile(clue, masterKey, "", "", "")
}

// GeneratePasswordWithProfile mengubah clue (atau data profil favorit) menjadi kombinasi leet
// dan menyisipkan angka yang diambil dari data profil user (seperti tanggal lahir).
func GeneratePasswordWithProfile(clue, masterKey, birthDate, favoriteFood, dreamCity string) string {
	// 1. Tentukan kata input utama jika belum diisi
	if strings.TrimSpace(clue) == "" {
		if favoriteFood != "" {
			clue = favoriteFood
		} else if dreamCity != "" {
			clue = dreamCity
		} else {
			clue = "CryptPass"
		}
	}

	// Hapus spasi agar password yang dihasilkan solid tanpa spasi (misal: "Nasi Goreng" -> "NasiGoreng")
	cleanWord := strings.ReplaceAll(clue, " ", "")

	var sb strings.Builder

	// 2. Transformasi karakter input menjadi variasi leet / case acak
	for _, ch := range cleanWord {
		lowerCh := unicode.ToLower(ch)
		if replacements, exists := leetMap[lowerCh]; exists {
			idx, err := cryptoRandInt(len(replacements))
			if err == nil {
				sb.WriteRune(replacements[idx])
				continue
			}
		}

		if unicode.IsLetter(ch) {
			isUpper, _ := cryptoRandInt(2)
			if isUpper == 1 {
				sb.WriteRune(unicode.ToUpper(ch))
			} else {
				sb.WriteRune(unicode.ToLower(ch))
			}
		} else {
			sb.WriteRune(ch)
		}
	}

	transformed := sb.String()

	// 3. Ambil angka dari data profil (tanggal lahir)
	numberSuffix := extractPersonalizedNumbers(birthDate)

	// 4. Tambahkan simbol
	randomSymbol1, _ := getRandomCharFrom(specialSymbols)
	randomSymbol2, _ := getRandomCharFrom(specialSymbols)

	// Kombinasikan: <TransformedClue><Symbol1><PersonalizedNumbers><Symbol2>
	// Contoh: R3nd4n9#17! atau T0ky0@98#
	return transformed + string(randomSymbol1) + numberSuffix + string(randomSymbol2)
}

// extractPersonalizedNumbers mengekstrak komponen angka dari tanggal lahir (YYYY-MM-DD atau DD-MM-YYYY)
func extractPersonalizedNumbers(birthDate string) string {
	if birthDate == "" {
		d1, _ := getRandomCharFrom(digitChars)
		d2, _ := getRandomCharFrom(digitChars)
		return string(d1) + string(d2)
	}

	// Cari semua angka dalam string birthDate
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(birthDate, -1)

	var candidateNumbers []string

	for _, match := range matches {
		if len(match) == 4 {
			// Tahun (contoh: 1998 -> "98" dan "1998")
			candidateNumbers = append(candidateNumbers, match[2:])
		} else if len(match) == 2 {
			// Hari atau Bulan (contoh: "17", "08")
			candidateNumbers = append(candidateNumbers, match)
		} else if len(match) == 1 {
			candidateNumbers = append(candidateNumbers, "0"+match)
		}
	}

	if len(candidateNumbers) > 0 {
		idx, err := cryptoRandInt(len(candidateNumbers))
		if err == nil {
			return candidateNumbers[idx]
		}
		return candidateNumbers[0]
	}

	// Fallback jika tidak ada angka yang dapat diekstrak
	d1, _ := getRandomCharFrom(digitChars)
	d2, _ := getRandomCharFrom(digitChars)
	return string(d1) + string(d2)
}

func cryptoRandInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func getRandomCharFrom(charSet string) (byte, error) {
	idx, err := cryptoRandInt(len(charSet))
	if err != nil {
		return charSet[0], err
	}
	return charSet[idx], nil
}

// GenerateMultiplePasswordsWithProfile menghasilkan sejumlah variasi password unik (default 3 opsi)
func GenerateMultiplePasswordsWithProfile(clue, masterKey, birthDate, favoriteFood, dreamCity string, count int) []string {
	if count <= 0 {
		count = 3
	}
	results := make([]string, 0, count)
	seen := make(map[string]bool)

	maxAttempts := count * 15
	attempts := 0

	for len(results) < count && attempts < maxAttempts {
		attempts++
		candidate := GeneratePasswordWithProfile(clue, masterKey, birthDate, favoriteFood, dreamCity)
		if !seen[candidate] {
			seen[candidate] = true
			results = append(results, candidate)
		}
	}

	// Fallback jika variasi sangat sedikit
	for len(results) < count {
		candidate := GeneratePasswordWithProfile(clue, masterKey, birthDate, favoriteFood, dreamCity)
		results = append(results, candidate)
	}

	return results
}

// GenerateMultiplePasswords menghasilkan sejumlah variasi password unik tanpa profil
func GenerateMultiplePasswords(clue string, masterKey string, count int) []string {
	return GenerateMultiplePasswordsWithProfile(clue, masterKey, "", "", "", count)
}
