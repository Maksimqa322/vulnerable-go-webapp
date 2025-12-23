package endpoints

import (
	"fmt"
	"net/http"
	"strconv"
)

// A06:2025 - Insecure Design
// 10 реалистичных эндпоинтов

// Уязвимость 1: Отсутствие rate limiting
func apiV1AuthLoginNoRateLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		_ = r.FormValue("password") // Не используется, но получаем для демонстрации
		
		// УЯЗВИМОСТЬ: Нет ограничения на количество попыток входа
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Login attempt for %s processed (no rate limiting!)", email),
			"warning": "Brute force attack possible",
		})
		return
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
				<button type="submit" class="btn">Login</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 2: Слабая валидация email
func apiV1UsersRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		
		// УЯЗВИМОСТЬ: Нет проверки формата email
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("User registered with email: %s (no validation!)", email),
		})
		return
	}
	
	html := renderPage("Register", `
		<div class="card">
			<h2>Register User</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="text" name="email" value="not-an-email">
				</div>
				<button type="submit" class="btn">Register</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 3: Отсутствие CAPTCHA
func apiV1Contact(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		_ = r.FormValue("message") // Не используется, но получаем для демонстрации
		
		// УЯЗВИМОСТЬ: Нет CAPTCHA, можно автоматизировать
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Contact form submitted (no CAPTCHA!)",
			"warning": "Spam/automation possible",
		})
		return
	}
	
	html := renderPage("Contact Us", `
		<div class="card">
			<h2>Contact Us</h2>
			<form method="POST">
				<div class="form-group">
					<label>Message</label>
					<textarea name="message">Hello</textarea>
				</div>
				<button type="submit" class="btn">Send</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 4: Небезопасный дизайн API - опасные действия через GET
func apiV1UsersDeleteGET(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	
	// УЯЗВИМОСТЬ: Удаление через GET запрос
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("User %s deleted via GET request (insecure design!)", userID),
		"warning": "CSRF attack possible",
	})
}

// Уязвимость 5: Отсутствие проверки бизнес-логики
func apiV1PaymentTransferNoCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		amount, _ := strconv.Atoi(r.FormValue("amount"))
		
		// УЯЗВИМОСТЬ: Можно перевести отрицательную сумму или больше баланса
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Transfer of %d completed (no balance check!)", amount),
			"warning": "Negative amounts or amounts exceeding balance are allowed",
		})
		return
	}
	
	html := renderPage("Transfer Money", `
		<div class="card">
			<h2>Transfer Money</h2>
			<form method="POST">
				<div class="form-group">
					<label>Amount</label>
					<input type="number" name="amount" value="-1000">
				</div>
				<button type="submit" class="btn">Transfer</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 6: Слабые требования к паролю
func apiV1UsersPasswordWeak(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		password := r.FormValue("password")
		
		// УЯЗВИМОСТЬ: Нет требований к сложности пароля
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Password '%s' accepted (no complexity requirements!)", password),
			"warning": "Weak passwords allowed",
		})
		return
	}
	
	html := renderPage("Change Password", `
		<div class="card">
			<h2>Change Password</h2>
			<form method="POST">
				<div class="form-group">
					<label>New Password</label>
					<input type="password" name="password" value="123">
				</div>
				<button type="submit" class="btn">Change</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 7: Отсутствие 2FA
func apiV1AuthVerifyNo2FA(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Нет двухфакторной аутентификации
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": "Authentication successful (no 2FA required!)",
		"warning": "Single factor authentication only",
	})
}

// Уязвимость 8: Небезопасный дизайн сессий
func apiV1SessionCreateInsecure(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Сессия не истекает и не привязана к IP
	sendJSON(w, map[string]interface{}{
		"status":      "success",
		"session_id":  "abc123def456",
		"expires":     "never",
		"ip_check":    "disabled",
		"warning":     "Session never expires and not bound to IP",
	})
}

// Уязвимость 9: Отсутствие аудита безопасности
func apiV1AdminAction(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	// УЯЗВИМОСТЬ: Критические действия не логируются
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Action '%s' executed (no audit log!)", action),
		"warning": "Security events not logged",
	})
}

// Уязвимость 10: Небезопасное восстановление пароля
func apiV1PasswordResetInsecure(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		
		// УЯЗВИМОСТЬ: Пароль отправляется сразу без проверки владельца email
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Password reset link sent to %s (no verification!)", email),
			"warning": "Account takeover possible",
		})
		return
	}
	
	html := renderPage("Reset Password", `
		<div class="card">
			<h2>Reset Password</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="victim@example.com">
				</div>
				<button type="submit" class="btn">Reset</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

