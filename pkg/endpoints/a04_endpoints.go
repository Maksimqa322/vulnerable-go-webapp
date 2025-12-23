package endpoints

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
)

// A04:2025 - Cryptographic Failures
// 10 реалистичных эндпоинтов

// Уязвимость 1: Хранение паролей в открытом виде в базе данных
func apiV1UsersPasswordPlain(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	
	// УЯЗВИМОСТЬ: Возвращаем пароли в открытом виде
	passwords := map[string]string{
		"1": "password123",
		"2": "admin123",
		"3": "SuperSecret2024",
	}
	
	if pass, ok := passwords[userID]; ok {
		sendJSON(w, map[string]interface{}{
			"status":   "success",
			"user_id":  userID,
			"password": pass, // Пароль в открытом виде!
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "User not found",
		})
	}
}

// Уязвимость 2: Использование MD5 для хеширования паролей
func apiV1AuthHash(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		password := r.FormValue("password")
		
		// УЯЗВИМОСТЬ: Используем MD5 для хеширования (легко взломать)
		hash := md5.Sum([]byte(password))
		sendJSON(w, map[string]interface{}{
			"status": "success",
			"hash":   fmt.Sprintf("%x", hash),
			"algorithm": "MD5 (INSECURE!)",
		})
		return
	}
	
	html := renderPage("Hash Password", `
		<div class="card">
			<h2>Hash Password (MD5)</h2>
			<form method="POST">
				<div class="form-group">
					<label>Password</label>
					<input type="password" name="password" value="mypassword">
				</div>
				<button type="submit" class="btn">Hash</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 3: Использование SHA1 для подписи
func apiV1ApiSign(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	
	// УЯЗВИМОСТЬ: Используем SHA1 для подписи (устарел)
	hash := sha1.Sum([]byte(data))
	sendJSON(w, map[string]interface{}{
		"status":    "success",
		"signature": fmt.Sprintf("%x", hash),
		"algorithm":  "SHA1 (DEPRECATED!)",
	})
}

// Уязвимость 4: Слабый ключ шифрования
func apiV1Encrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		data := r.FormValue("data")
		key := "12345" // Слабый ключ
		
		// УЯЗВИМОСТЬ: Простое XOR шифрование с слабым ключом
		encrypted := make([]byte, len(data))
		for i := range data {
			encrypted[i] = data[i] ^ key[i%len(key)]
		}
		
		sendJSON(w, map[string]interface{}{
			"status":    "success",
			"encrypted": base64.StdEncoding.EncodeToString(encrypted),
			"key_length": len(key),
			"warning":   "Weak encryption key used",
		})
		return
	}
	
	html := renderPage("Encrypt Data", `
		<div class="card">
			<h2>Encrypt Data</h2>
			<form method="POST">
				<div class="form-group">
					<label>Data to Encrypt</label>
					<textarea name="data">secret information</textarea>
				</div>
				<button type="submit" class="btn">Encrypt</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 5: API ключи в открытом виде в коде
func apiV1ConfigKeys(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: API ключи захардкожены в коде
	sendJSON(w, map[string]interface{}{
		"api_keys": map[string]string{
			"stripe_secret":  "sk_live_51Hqw2LKD8vqX8Z4EXAMPLE",
			"aws_access_key": "AKIAIOSFODNN7EXAMPLE",
			"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"jwt_secret":     "my-super-secret-jwt-key-12345",
		},
		"warning": "Keys exposed in source code",
	})
}

// Уязвимость 6: Использование HTTP вместо HTTPS
func apiV1PaymentProcessHTTP(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Платежи обрабатываются через HTTP
	if r.TLS == nil {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Payment processed over HTTP (INSECURE!)",
			"warning": "Credit card data transmitted in plain text",
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Payment processed over HTTPS",
		})
	}
}

// Уязвимость 7: Слабая генерация токенов
func apiV1AuthToken(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Токен генерируется на основе времени (предсказуемо)
	token := fmt.Sprintf("token_%s", r.Header.Get("Date"))
	
	sendJSON(w, map[string]interface{}{
		"status": "success",
		"token":  token,
		"warning": "Token generated using predictable method",
	})
}

// Уязвимость 8: Небезопасный обмен ключами
func apiV1KeyExchange(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Ключ отправляется в открытом виде
	sendJSON(w, map[string]interface{}{
		"status": "success",
		"shared_key": "abc123def456",
		"method": "Plain text key exchange (INSECURE!)",
	})
}

// Уязвимость 9: Отсутствие проверки сертификата SSL
func apiV1ExternalApi(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	
	// УЯЗВИМОСТЬ: Запрос к внешнему API без проверки сертификата
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Request to %s completed without SSL certificate verification", url),
		"warning": "MITM attack possible",
	})
}

// Уязвимость 10: Утечка ключей через логи
func apiV1ApiCall(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("api_key")
	
	// УЯЗВИМОСТЬ: API ключ логируется в открытом виде
	fmt.Printf("[LOG] API call with key: %s\n", apiKey)
	
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": "API call processed",
		"warning": "API key logged in plain text",
	})
}

