# Crypt-Pass API Documentation

Dokumentasi lengkap REST API untuk **Crypt-Pass** (Password Manager Backend dengan Multi-Database Vault & Enkripsi AES-256-GCM).

---

## 📌 Informasi Umum

* **Base URL:** `http://localhost:8080/api/v1`
* **Format Data:** `application/json`
* **Autentikasi:** JWT Bearer Token (`Authorization: Bearer <access_token>`)
* **Validasi Skema (Strict):** Request body divalidasi secara ketat (`DisallowUnknownFields`). Jika terdapat field asing yang tidak sesuai kontrak, server akan mengembalikan status `400 Bad Request`.

---

## 📑 Daftar Endpoint

| Modul | Method | Endpoint | Auth | Deskripsi |
| :--- | :--- | :--- | :---: | :--- |
| **Auth** | `POST` | `/auth/register` | Publik | Registrasi akun user baru dengan profil personal |
| **Auth** | `POST` | `/auth/login` | Publik | Login user & penerbitan Access + Refresh Token |
| **Auth** | `POST` | `/auth/refresh` | Publik | Memperbarui Access Token menggunakan Refresh Token |
| **Auth** | `POST` | `/auth/logout` | Publik | Mencabut (*revoke*) Refresh Token |
| **Auth** | `POST` | `/auth/recover` | Publik | Pemulihan akun & reset master password via Emergency Kit |
| **Auth** | `GET` | `/auth/me` | 🔒 JWT | Mengambil data profil user yang sedang login |
| **Vault** | `POST` | `/passwords/generate` | 🔒 JWT | Men-generate 3 saran password berbasis profil user |
| **Vault** | `POST` | `/passwords` | 🔒 JWT | Menyimpan password terpilih ke database Vault (Terenkripsi AES-256) |
| **Vault** | `GET` | `/passwords` | 🔒 JWT | Mengambil list (password tersembunyi) atau detail (password didekripsi) |
| **Vault** | `DELETE` | `/passwords` | 🔒 JWT | Soft delete password kredensial |

---

## 🔐 1. Modul Autentikasi (`/auth`)

### 1.1. Register User
Mendaftarkan pengguna baru ke Auth Database beserta data profil untuk personalisasi generator password.

* **URL:** `POST /api/v1/auth/register`
* **Headers:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "name": "Aldi Murad",
  "email": "user@example.com",
  "password": "MasterPassword123!",
  "birth_date": "1998-08-17",
  "favorite_food": "Rendang",
  "dream_city": "Tokyo"
}
```

> **Catatan:** `backup_salt` dibuat secara otomatis (cryptographically secure random token) oleh server saat registrasi dan dikembalikan pada response untuk disimpan di Emergency Kit pengguna.

* **Response (`201 Created`):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": "7b58c707-1b0a-49a6-8968-07e15f3e7ef1",
    "name": "Aldi Murad",
    "email": "user@example.com",
    "backup_salt": "a4f891b2c6e83d710f45a19c3b827e40",
    "birth_date": "1998-08-17",
    "favorite_food": "Rendang",
    "dream_city": "Tokyo"
  }
}
```

---

### 1.2. Login
Melakukan autentikasi menggunakan email dan master password.

* **URL:** `POST /api/v1/auth/login`
* **Headers:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "email": "user@example.com",
  "password": "MasterPassword123!"
}
```

* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    "refresh_token": "8f3b6c2d-1a4e-4f7a-9b1c-3d2e5a6f7b8c",
    "expires_in": 900,
    "user": {
      "id": "7b58c707-1b0a-49a6-8968-07e15f3e7ef1",
      "name": "Aldi Murad",
      "email": "user@example.com"
    }
  }
}
```

---

### 1.3. Refresh Token
Memperbarui access token yang kedaluwarsa menggunakan refresh token (dengan mekanisme *Token Rotation*).

* **URL:** `POST /api/v1/auth/refresh`
* **Headers:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "refresh_token": "8f3b6c2d-1a4e-4f7a-9b1c-3d2e5a6f7b8c"
}
```

* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    "refresh_token": "4a7b3c8d-9e1f-2a3b-4c5d-6e7f8a9b0c1d",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

---

### 1.4. Logout
Mencabut status refresh token saat pengguna logout.

* **URL:** `POST /api/v1/auth/logout`
* **Headers:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "refresh_token": "8f3b6c2d-1a4e-4f7a-9b1c-3d2e5a6f7b8c"
}
```

* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### 1.5. Get Profile
Mengambil data profil pengguna yang sedang login.

* **URL:** `GET /api/v1/auth/me`
* **Headers:** `Authorization: Bearer <access_token>`
* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Profile fetched successfully",
  "data": {
    "id": "7b58c707-1b0a-49a6-8968-07e15f3e7ef1",
    "name": "Aldi Murad",
    "email": "user@example.com",
    "backup_salt": "a4f891b2c6e83d710f45a19c3b827e40",
    "birth_date": "1998-08-17",
    "favorite_food": "Rendang",
    "dream_city": "Tokyo"
  }
}
```

---

### 1.6. Recover Account (Emergency Kit Recovery)
Memulihkan akun dan mereset Master Password menggunakan `backup_salt` dari Emergency Kit dan verifikasi profil personal (`birth_date`, `favorite_food`, `dream_city`). Seluruh sesi token lama otomatis dicabut setelah reset berhasil.

* **URL:** `POST /api/v1/auth/recover`
* **Headers:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "email": "user@example.com",
  "backup_salt": "a4f891b2c6e83d710f45a19c3b827e40",
  "birth_date": "1998-08-17",
  "favorite_food": "Rendang",
  "dream_city": "Tokyo",
  "new_password": "NewMasterPassword123!"
}
```

* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Account master password reset successfully"
}
```

---

## 🔑 2. Modul Password Manager & Vault (`/passwords`)

### 2.1. Generate Password Suggestions
Menghasilkan **3 pilihan kandidat password unik** berdasarkan kata masukan user dan profil personalnya (`birth_date`, `favorite_food`, `dream_city`).

* **URL:** `POST /api/v1/passwords/generate`
* **Headers:** 
  * `Authorization: Bearer <access_token>`
  * `Content-Type: application/json`
* **Request Body:**
```json
{
  "password": "nasigoreng"
}
```

* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Password suggestions generated successfully",
  "data": {
    "suggestions": [
      "N4s19or3ng#17!",
      "n@$i6Or3Ng?98$",
      "N@$I9OR3N9@08*"
    ],
    "password": "nasigoreng",
    "count": 3
  }
}
```

---

### 2.2. Simpan Password (Create Vault Entry)
Menyimpan password yang telah dipilih user dari generator ke database Vault. Password otomatis dienkripsi dengan **AES-256-GCM** sebelum disimpan ke database.

* **URL:** `POST /api/v1/passwords`
* **Headers:** 
  * `Authorization: Bearer <access_token>`
  * `Content-Type: application/json`
* **Request Body:**
```json
{
  "title": "Akun Gmail Kantor",
  "clue": "nasigoreng",
  "password": "N4s19or3ng#17!"
}
```

* **Response (`201 Created`):**
```json
{
  "success": true,
  "message": "Password created successfully",
  "data": {
    "id": "e4b2d1c0-5a3f-4e6b-9c2d-1a2b3c4d5e6f",
    "user_id": "7b58c707-1b0a-49a6-8968-07e15f3e7ef1",
    "title": "Akun Gmail Kantor",
    "clue": "nasigoreng",
    "password_encrypted": "N4s19or3ng#17!",
    "is_deleted": false,
    "is_dirty": false,
    "created_at": "2026-09-14T10:30:00Z",
    "updated_at": "2026-09-14T10:30:00Z"
  }
}
```

---

### 2.3. Get Passwords (List vs Detail)
Mengambil daftar password atau detail satu password spesifik:
* **List View (`GET /api/v1/passwords`):** Nilai password **disembunyikan (tidak dikembalikan)** demi keamanan agar tidak terekspos sekaligus di awal.
* **Detail View (`GET /api/v1/passwords?id=<id>` atau `?title=<title>`):** Password **didekripsi dan dikembalikan pada `password_encrypted`** (digunakan saat frontend telah memverifikasi PIN / biometrik / password pengguna).

* **URL:** `GET /api/v1/passwords`
* **Headers:** `Authorization: Bearer <access_token>`

#### 1. Ambil List Password (Tanpa Reveal Password)
* **Request:** `GET /api/v1/passwords`
* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Passwords retrieved successfully",
  "data": [
    {
      "id": "e4b2d1c0-5a3f-4e6b-9c2d-1a2b3c4d5e6f",
      "user_id": "7b58c707-1b0a-49a6-8968-07e15f3e7ef1",
      "title": "Akun Gmail Kantor",
      "clue": "nasigoreng",
      "is_deleted": false,
      "is_dirty": false,
      "created_at": "2026-09-14T10:30:00Z",
      "updated_at": "2026-09-14T10:30:00Z"
    }
  ]
}
```

#### 2. Ambil Detail Password (Reveal Password Didekripsi)
* **Request by ID:** `GET /api/v1/passwords?id=e4b2d1c0-5a3f-4e6b-9c2d-1a2b3c4d5e6f`
* **Request by Title:** `GET /api/v1/passwords?title=Akun Gmail Kantor`
* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Password retrieved successfully",
  "data": {
    "id": "e4b2d1c0-5a3f-4e6b-9c2d-1a2b3c4d5e6f",
    "user_id": "7b58c707-1b0a-49a6-8968-07e15f3e7ef1",
    "title": "Akun Gmail Kantor",
    "clue": "nasigoreng",
    "password_encrypted": "N4s19or3ng#17!",
    "is_deleted": false,
    "is_dirty": false,
    "created_at": "2026-09-14T10:30:00Z",
    "updated_at": "2026-09-14T10:30:00Z"
  }
}
```

---

### 2.4. Soft Delete Password
Menandai item kredensial sebagai terhapus (`is_deleted = true`).

* **URL:** `DELETE /api/v1/passwords?id=e4b2d1c0-5a3f-4e6b-9c2d-1a2b3c4d5e6f`
* **Headers:** `Authorization: Bearer <access_token>`
* **Response (`200 OK`):**
```json
{
  "success": true,
  "message": "Password deleted successfully"
}
```

---

## ⚠️ Format Respon Error (Standard Error Response)

Semua error mengikuti struktur JSON standar:

```json
{
  "success": false,
  "error": "<Pesan Error>"
}
```

### Contoh Status Code:
* **`400 Bad Request`**: Request body tidak valid, field wajib kosong, atau terdapat field asing yang tidak didefinisikan.
* **`401 Unauthorized`**: Token JWT tidak valid, tidak disertakan, atau sudah kedaluwarsa.
* **`404 Not Found`**: Data kredensial / user tidak ditemukan.
* **`405 Method Not Allowed`**: HTTP Method yang digunakan tidak didukung pada endpoint tersebut.
* **`500 Internal Server Error`**: Terjadi kesalahan internal pada server / database.
