package endpoints

import (
	"fmt"
	"net/http"
)

// A07:2025 - Authentication Failures
// 10 реалистичных эндпоинтов

var userDB = map[string]string{
	"admin@company.com": "admin123",
	"user@company.com": "password",
}

// Уязвимость 1: Слабые пароли по умолчанию
func apiV1AuthDefaultLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		
		// УЯЗВИМОСТЬ: Пароли по умолчанию не изменены
		if userDB[email] == password {
			sendJSON(w, map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Login successful for %s (default password not changed!)", email),
				"warning": "Default credentials still active",
			})
		} else {
			sendJSON(w, map[string]interface{}{
				"status":  "error",
				"message": "Invalid credentials",
			})
		}
		return
	}
	
	html := renderPage("Login (Default Credentials)", `
		<div class="card">
			<h2>Login</h2>
			<p>Default: admin@company.com / admin123</p>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="admin@company.com">
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" value="admin123">
				</div>
				<button type="submit" class="btn">Login</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 2: Отсутствие блокировки после неудачных попыток
func apiV1AuthBruteforce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		
		// УЯЗВИМОСТЬ: Нет блокировки, можно брутфорсить
		if userDB[email] == password {
			sendJSON(w, map[string]interface{}{
				"status": "success",
				"message": "Login successful",
			})
		} else {
			sendJSON(w, map[string]interface{}{
				"status":  "error",
				"message": "Invalid credentials (unlimited attempts allowed!)",
			})
		}
		return
	}
	
	html := renderPage("Login (No Rate Limit)", `
		<div class="card">
			<h2>Login</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="user@company.com">
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" value="wrong">
				</div>
				<button type="submit" class="btn">Login</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 3: Пароли в открытом виде в базе
func apiV1UsersPasswordDB(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	
	// УЯЗВИМОСТЬ: Пароли хранятся в открытом виде
	passwords := map[string]string{
		"1": "password123",
		"2": "admin456",
	}
	
	if pass, ok := passwords[userID]; ok {
		sendJSON(w, map[string]interface{}{
			"status":   "success",
			"user_id":  userID,
			"password": pass,
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "User not found",
		})
	}
}

// Уязвимость 4: Слабая проверка сессии
func apiV1SessionVerify(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	
	// УЯЗВИМОСТЬ: Любая строка принимается как валидная сессия
	if len(sessionID) > 0 {
		sendJSON(w, map[string]interface{}{
			"status":    "success",
			"session_id": sessionID,
			"message":   "Session verified (no actual validation!)",
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Session ID required",
		})
	}
}

// Уязвимость 5: Сессия никогда не истекает
func apiV1SessionInfo(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Сессия активна навсегда
	sendJSON(w, map[string]interface{}{
		"status":     "active",
		"expires_at": "never",
		"created_at": "2024-01-01T00:00:00Z",
		"warning":    "Session never expires",
	})
}

// Уязвимость 6: Небезопасное восстановление пароля
func apiV1PasswordResetAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		
		// УЯЗВИМОСТЬ: Новый пароль отправляется сразу без проверки
		if pass, ok := userDB[email]; ok {
			sendJSON(w, map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("New password sent to %s: %s (no verification!)", email, pass),
			})
		} else {
			sendJSON(w, map[string]interface{}{
				"status":  "error",
				"message": "User not found",
			})
		}
		return
	}
	
	html := renderPage("Reset Password", `
		<div class="card">
			<h2>Reset Password</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="user@company.com">
				</div>
				<button type="submit" class="btn">Reset</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 7: Отсутствие 2FA
func apiV1AuthLoginNo2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		
		// УЯЗВИМОСТЬ: Вход без двухфакторной аутентификации
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Login successful for %s (no 2FA required!)", email),
			"token":   "jwt_token_abc123",
		})
		return
	}
	
	html := renderPage("Login (No 2FA)", `
		<div class="card">
			<h2>Login</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="user@company.com">
				</div>
				<button type="submit" class="btn">Login</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 8: Подделка сессий
func apiV1SessionCreateForgery(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	
	// УЯЗВИМОСТЬ: Можно подделать сессию, зная формат
	if sessionID == "admin_session_123" {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Admin session created (session ID predictable!)",
			"role":    "admin",
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "User session created",
			"role":    "user",
		})
	}
}

// Уязвимость 9: Отсутствие проверки IP адреса
func apiV1SessionValidate(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Сессия валидна с любого IP
	sendJSON(w, map[string]interface{}{
		"status":    "valid",
		"ip_check":  "disabled",
		"message":   "Session valid from any IP address",
		"warning":   "Session hijacking possible",
	})
}

// Уязвимость 10: Утечка учетных данных в логах
func apiV1AuthLoginLog(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		
		// УЯЗВИМОСТЬ: Учетные данные логируются в открытом виде
		fmt.Printf("[LOG] Login attempt - email: %s, password: %s\n", email, password)
		
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Login processed (credentials logged in plain text!)",
		})
		return
	}
	
	html := renderPage("Login (Credentials Logged)", `
		<div class="card">
			<h2>Login</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="user@company.com">
				</div>
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" value="secret123">
				</div>
				<button type="submit" class="btn">Login</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

