package endpoints

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// A01:2025 - Broken Access Control
// 10 реалистичных эндпоинтов с уязвимостями

// Уязвимость 1: IDOR в API получения профиля пользователя
func apiV1UsersID(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID из пути /api/v1/users/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID := path

	// УЯЗВИМОСТЬ: Нет проверки, что пользователь запрашивает только свой профиль
	// Любой может получить данные любого пользователя, зная ID

	users := map[string]map[string]string{
		"1": {"id": "1", "email": "john.doe@company.com", "phone": "+1234567890", "balance": "50000", "ssn": "123-45-6789"},
		"2": {"id": "2", "email": "jane.smith@company.com", "phone": "+0987654321", "balance": "75000", "ssn": "987-65-4321"},
		"3": {"id": "3", "email": "admin@company.com", "phone": "+1111111111", "balance": "100000", "ssn": "000-00-0000", "role": "admin"},
	}

	if user, ok := users[userID]; ok {
		sendJSON(w, map[string]interface{}{
			"status": "success",
			"data":   user,
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "User not found",
		})
	}
}

// Уязвимость 2: Обход авторизации через параметр is_admin
func apiV1AdminUsers(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Проверка админ прав через GET параметр
	isAdmin := r.URL.Query().Get("is_admin")

	if isAdmin == "true" || isAdmin == "1" {
		users := []map[string]string{
			{"id": "1", "email": "user1@test.com", "role": "user"},
			{"id": "2", "email": "user2@test.com", "role": "user"},
			{"id": "3", "email": "admin@test.com", "role": "admin"},
		}
		sendJSON(w, map[string]interface{}{
			"status": "success",
			"data":   users,
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Access denied",
		})
	}
}

// Уязвимость 3: Небезопасный редирект после логина
func apiV1AuthLoginRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		redirect := r.FormValue("redirect")
		// УЯЗВИМОСТЬ: Редирект на любой URL без проверки
		if redirect != "" {
			http.Redirect(w, r, redirect, 302)
			return
		}
	}

	html := renderPage("Login", `
		<div class="card">
			<h2>User Login</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="user@example.com">
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" value="password123">
				</div>
				<div class="form-group">
					<label>Redirect URL (after login)</label>
					<input type="text" name="redirect" value="/dashboard">
				</div>
				<button type="submit" class="btn">Login</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 4: Слабая проверка JWT токена
func apiV1AuthVerifyJWT(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	// УЯЗВИМОСТЬ: Принимаем любой токен, который содержит "admin"
	if strings.Contains(token, "admin") {
		sendJSON(w, map[string]interface{}{
			"status": "success",
			"user":   "admin",
			"role":   "administrator",
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Invalid token",
		})
	}
}

// Уязвимость 5: Доступ к файлам через прямой путь
func apiV1Files(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")

	// УЯЗВИМОСТЬ: Нет проверки пути, можно читать любые файлы
	if file == "config.json" {
		w.Write([]byte(`{"database": "postgresql://admin:password@db:5432/prod", "api_key": "sk_live_1234567890"}`))
	} else if file == "users.db" {
		w.Write([]byte("SQLite database content..."))
	} else {
		w.Write([]byte(fmt.Sprintf("File content: %s", file)))
	}
}

// Уязвимость 6: Обход через заголовок X-Admin
func apiV1AdminConfig(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Проверка админ прав через заголовок, который можно подделать
	if r.Header.Get("X-Admin") == "true" || r.Header.Get("X-User-Role") == "admin" {
		sendJSON(w, map[string]interface{}{
			"status": "success",
			"config": map[string]string{
				"database_url": "postgresql://admin:secret@db:5432",
				"redis_url":    "redis://admin:pass@redis:6379",
				"api_secret":   "super_secret_key_12345",
			},
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Admin access required",
		})
	}
}

// Уязвимость 7: CORS misconfiguration - разрешаем всем доменам
func apiV1UserProfile(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// УЯЗВИМОСТЬ: Разрешаем CORS для любого домена
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
	}

	sendJSON(w, map[string]interface{}{
		"status": "success",
		"user": map[string]string{
			"id":    "123",
			"email": "user@example.com",
			"token": "sensitive_token_abc123",
		},
	})
}

// Уязвимость 8: Race condition в изменении баланса
func apiV1PaymentTransferRace(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		amount, _ := strconv.Atoi(r.FormValue("amount"))
		toUser := r.FormValue("to_user")

		// УЯЗВИМОСТЬ: Нет блокировки, можно отправить несколько запросов одновременно
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Transferred %d to user %s", amount, toUser),
		})
		return
	}

	html := renderPage("Transfer Money", `
		<div class="card">
			<h2>Transfer Payment</h2>
			<form method="POST">
				<div class="form-group">
					<label>Amount</label>
					<input type="number" name="amount" value="1000">
				</div>
				<div class="form-group">
					<label>To User ID</label>
					<input type="text" name="to_user" value="2">
				</div>
				<button type="submit" class="btn">Transfer</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 9: Прямой доступ к админ панели без проверки сессии
func apiV1AdminDashboard(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Нет проверки сессии, достаточно знать URL
	html := renderPage("Admin Dashboard", `
		<div class="card">
			<h2>Admin Dashboard</h2>
			<p>Total Users: 1,234</p>
			<p>Active Sessions: 567</p>
			<p>Database: Connected</p>
			<p>API Keys: sk_live_abc123, sk_live_def456</p>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 10: Обход через параметр bypass_auth
func apiV1UserSettings(w http.ResponseWriter, r *http.Request) {
	bypass := r.URL.Query().Get("bypass_auth")

	// УЯЗВИМОСТЬ: Параметр для обхода авторизации в production
	if bypass == "true" || r.URL.Query().Get("debug") == "1" {
		sendJSON(w, map[string]interface{}{
			"status": "success",
			"settings": map[string]string{
				"email":       "user@example.com",
				"2fa_enabled": "false",
				"api_key":     "sk_live_user_key_12345",
				"webhook_url": "https://user-site.com/webhook",
			},
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Authentication required",
		})
	}
}
