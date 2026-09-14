package password_manager

import (
	"context"
	"strings"
	"testing"
	"unicode"

	entity "crypt-pass/internal/password_manager/entity"

	"github.com/google/uuid"
)

func TestGeneratePassword(t *testing.T) {
	clue := "NasiGoreng"
	masterKey := "MyMasterKey123!"

	password := GeneratePassword(clue, masterKey)

	// 1. Password tidak boleh kosong
	if password == "" {
		t.Fatal("expected password to not be empty")
	}

	// 2. Panjang password harus minimal sama dengan clue + 4 (2 simbol + 2 digit)
	if len(password) < len(clue)+4 {
		t.Errorf("expected password length at least %d, got %d (password: %s)", len(clue)+4, len(password), password)
	}

	// 3. Password harus mengandung angka
	hasDigit := false
	for _, ch := range password {
		if unicode.IsDigit(ch) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		t.Errorf("expected password to contain at least one digit, got %s", password)
	}

	// 4. Password harus mengandung setidaknya satu simbol khusus
	hasSymbol := false
	for _, ch := range password {
		if strings.ContainsRune(specialSymbols, ch) {
			hasSymbol = true
			break
		}
	}
	if !hasSymbol {
		t.Errorf("expected password to contain at least one special symbol, got %s", password)
	}
}

func TestGeneratePasswordWithProfile(t *testing.T) {
	birthDate := "1998-08-17"
	favoriteFood := "Rendang"
	dreamCity := "Tokyo"

	// Test 1: Generate dengan data profil lengkap
	password := GeneratePasswordWithProfile("", "key123", birthDate, favoriteFood, dreamCity)
	if password == "" {
		t.Fatal("expected password to not be empty")
	}

	// Memastikan angka yang dihasilkan berasal dari tanggal lahir (17, 08, atau 98)
	containsBirthComponent := strings.Contains(password, "17") || strings.Contains(password, "08") || strings.Contains(password, "98")
	if !containsBirthComponent {
		t.Errorf("expected password to contain birth date number component (17, 08, or 98), got: %s", password)
	}

	// Test 2: Fallback ke dreamCity saat clue dan favoriteFood kosong
	passwordCity := GeneratePasswordWithProfile("", "key123", "2002-12-05", "", "Kyoto")
	containsYearOrDay := strings.Contains(passwordCity, "02") || strings.Contains(passwordCity, "12") || strings.Contains(passwordCity, "05")
	if !containsYearOrDay {
		t.Errorf("expected password to contain birth numbers (02, 12, or 05), got: %s", passwordCity)
	}
}

func TestGeneratePassword_EmptyClue(t *testing.T) {
	password := GeneratePassword("", "someMasterKey")
	if password == "" {
		t.Fatal("expected fallback password to not be empty")
	}
	if len(password) < 4 {
		t.Fatalf("expected fallback password to have sufficient length, got %s", password)
	}
}

func TestGeneratePassword_Randomness(t *testing.T) {
	clue := "NasiGoreng"
	pass1 := GeneratePassword(clue, "key1")
	pass2 := GeneratePassword(clue, "key1")

	// Menghasilkan output acak setiap kali dipanggil
	if pass1 == pass2 {
		t.Logf("Warning: Two consecutive generations yielded the same result (%s), checking over 5 iterations", pass1)
		allSame := true
		for i := 0; i < 5; i++ {
			if GeneratePassword(clue, "key1") != pass1 {
				allSame = false
				break
			}
		}
		if allSame {
			t.Error("expected randomness in password generation, but got identical results")
		}
	}
}

type mockPasswordRepo struct {
	data map[uuid.UUID]*entity.Credentials
}

func (m *mockPasswordRepo) Create(ctx context.Context, cred *entity.Credentials) error {
	m.data[cred.ID] = cred
	return nil
}

func (m *mockPasswordRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.Credentials, error) {
	return m.data[id], nil
}

func (m *mockPasswordRepo) GetByUserIDAndID(ctx context.Context, userID uuid.UUID, id uuid.UUID) (*entity.Credentials, error) {
	for _, c := range m.data {
		if c.ID == id && c.UserID == userID && !c.IsDeleted {
			return c, nil
		}
	}
	return nil, nil
}

func (m *mockPasswordRepo) GetByUserIDAndTitle(ctx context.Context, userID uuid.UUID, title string) (*entity.Credentials, error) {
	for _, c := range m.data {
		if c.UserID == userID && c.Title == title && !c.IsDeleted {
			return c, nil
		}
	}
	return nil, nil
}

func (m *mockPasswordRepo) GetByUserID(ctx context.Context, userID uuid.UUID) ([]entity.Credentials, error) {
	var list []entity.Credentials
	for _, c := range m.data {
		if c.UserID == userID && !c.IsDeleted {
			list = append(list, *c)
		}
	}
	return list, nil
}

func (m *mockPasswordRepo) Update(ctx context.Context, cred *entity.Credentials) error {
	m.data[cred.ID] = cred
	return nil
}

func (m *mockPasswordRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if c, ok := m.data[id]; ok {
		c.IsDeleted = true
	}
	return nil
}

func (m *mockPasswordRepo) SoftDelete(ctx context.Context, userID uuid.UUID, id uuid.UUID) error {
	for _, c := range m.data {
		if c.ID == id && c.UserID == userID && !c.IsDeleted {
			c.IsDeleted = true
			return nil
		}
	}
	return nil
}

func TestService_CreateAndGetPasswordEncryption(t *testing.T) {
	repo := &mockPasswordRepo{data: make(map[uuid.UUID]*entity.Credentials)}
	svc := NewPasswordManagerService(repo, nil, "my-secret-vault-key-12345678901")

	userID := uuid.New()
	chosenPassword := "R3nd4n9#17!" // Password hasil pilihan user dari generator
	created, err := svc.CreatePassword(context.Background(), userID, "TestSite", "clue1", chosenPassword, "")
	if err != nil {
		t.Fatalf("failed to create password: %v", err)
	}

	// 1. Return object dari CreatePassword menampilkan password pilihan user (plaintext)
	if created.PasswordEncrypted != chosenPassword {
		t.Errorf("expected returned credential to have chosen password, got %s", created.PasswordEncrypted)
	}

	// 2. Data yang tersimpan di repository harus terenkripsi (tidak sama dengan plain text)
	storedInDB := repo.data[created.ID]
	if storedInDB.PasswordEncrypted == chosenPassword {
		t.Errorf("expected stored password in DB to be encrypted, but got plaintext")
	}

	// 3. GetPassword mengambil data dari DB dan mendekripsinya kembali ke chosenPassword
	retrieved, err := svc.GetPassword(context.Background(), userID, created.ID)
	if err != nil {
		t.Fatalf("failed to get password: %v", err)
	}

	if retrieved.PasswordEncrypted != chosenPassword {
		t.Errorf("expected retrieved password to be decrypted to %q, got %q", chosenPassword, retrieved.PasswordEncrypted)
	}
}

func TestGenerateMultiplePasswordsWithProfile(t *testing.T) {
	suggestions := GenerateMultiplePasswordsWithProfile("Nasi Goreng", "", "1998-08-17", "Rendang", "Tokyo", 3)
	if len(suggestions) != 3 {
		t.Fatalf("expected 3 suggestions, got %d", len(suggestions))
	}
	for i, s := range suggestions {
		if s == "" {
			t.Errorf("suggestion %d is empty", i)
		}
	}
}
