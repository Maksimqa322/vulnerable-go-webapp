package endpoints

import (
	"fmt"
	"net/http"
)

// A09:2025 - Security Logging and Alerting Failures
// 10 реалистичных эндпоинтов

// Уязвимость 1: Критические действия не логируются
func apiV1UsersDeleteNoLog(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	
	// УЯЗВИМОСТЬ: Удаление пользователя не логируется
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("User %s deleted (no audit log!)", userID),
		"warning": "Security event not logged",
	})
}

// Уязвимость 2: Чувствительные данные в логах
func apiV1AuthLoginLogSensitive(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		
		// УЯЗВИМОСТЬ: Пароль логируется в открытом виде
		fmt.Printf("[LOG] Login attempt - email: %s, password: %s\n", email, password)
		
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Login successful (password logged in plain text!)",
		})
		return
	}
	
	html := renderPage("Login", `
		<div class="card">
			<h2>Login</h2>
			<form method="POST">
				<div class="form-group">
					<label>Email</label>
					<input type="email" name="email" value="user@example.com">
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

// Уязвимость 3: Мониторинг не настроен
func apiV1SystemStatus(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Нет мониторинга подозрительной активности
	sendJSON(w, map[string]interface{}{
		"status":    "operational",
		"monitoring": "disabled",
		"warning":   "No security monitoring enabled",
	})
}

// Уязвимость 4: Недостаточное логирование
func apiV1PaymentProcessInsufficientLog(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		amount := r.FormValue("amount")
		
		// УЯЗВИМОСТЬ: Логируется только сумма, без IP, времени, пользователя
		fmt.Printf("[LOG] Payment: %s\n", amount)
		
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Payment processed: %s (insufficient logging!)", amount),
			"warning": "Missing: IP address, timestamp, user ID, transaction ID",
		})
		return
	}
	
	html := renderPage("Process Payment", `
		<div class="card">
			<h2>Process Payment</h2>
			<form method="POST">
				<div class="form-group">
					<label>Amount</label>
					<input type="number" name="amount" value="1000">
				</div>
				<button type="submit" class="btn">Process</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 5: Отсутствие алертов
func apiV1AuthFailedLogin(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Нет алерта при множественных неудачных попытках
	sendJSON(w, map[string]interface{}{
		"status":  "error",
		"message": "Login failed (no alert sent!)",
		"warning": "Brute force attack not detected",
	})
}

// Уязвимость 6: Логи в открытом доступе
func apiV1LogsAccess(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Логи доступны без аутентификации
	w.Write([]byte(`2024-01-15 10:30:15 [INFO] User login: admin@company.com
2024-01-15 10:30:20 [INFO] API call: GET /api/v1/users/123
2024-01-15 10:30:25 [ERROR] Database connection: postgresql://admin:password@db:5432
2024-01-15 10:30:30 [INFO] Payment: amount=1000, user_id=123, card=****1234
2024-01-15 10:30:35 [DEBUG] JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
2024-01-15 10:30:40 [INFO] Password reset: user@company.com, token=abc123`))
}

// Уязвимость 7: Отсутствие корреляции событий
func apiV1EventsList(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: События не коррелируются
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": "Events listed (no correlation!)",
		"warning": "Attack patterns cannot be detected",
	})
}

// Уязвимость 8: Недостаточная детализация логов
func apiV1ActionExecute(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	// УЯЗВИМОСТЬ: Логируется только действие, без деталей
	fmt.Printf("[LOG] Action: %s\n", action)
	
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Action '%s' executed (insufficient details in log!)", action),
		"warning": "Missing: user, IP, timestamp, parameters, result",
	})
}

// Уязвимость 9: Анализ логов не выполняется
func apiV1LogsAnalyze(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Логи не анализируются автоматически
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": "Log analysis disabled",
		"warning": "Suspicious activity not detected automatically",
	})
}

// Уязвимость 10: Логи хранятся небезопасно
func apiV1LogsStorage(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Логи хранятся в открытом виде без шифрования
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"storage": "/var/log/app/access.log (unencrypted!)",
		"warning": "Logs accessible without encryption",
	})
}

