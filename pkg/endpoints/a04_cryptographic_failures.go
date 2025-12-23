package endpoints

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
)

// A04:2025 - Cryptographic Failures
// 10 уязвимостей разной сложности

func a04CryptographicFailures(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A04: Cryptographic Failures</h1>
	<h2>Уязвимость 1 (Легкая): Хранение паролей в открытом виде</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="1">
		Username: <input type="text" name="user" value="admin">
		<button>Показать пароль</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Использование MD5</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="2">
		Password: <input type="text" name="pass" value="mypassword">
		<button>Хешировать MD5</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Использование SHA1</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="3">
		Password: <input type="text" name="pass" value="mypassword">
		<button>Хешировать SHA1</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Слабый ключ шифрования</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="4">
		Data: <input type="text" name="data" value="secret">
		<button>Зашифровать</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Хранение ключей в коде</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="5">
		<button>Показать ключи</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Использование HTTP вместо HTTPS</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="6">
		<button>Проверить протокол</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Слабая генерация случайных чисел</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="7">
		<button>Сгенерировать токен</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Небезопасный обмен ключами</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="8">
		<button>Обменять ключи</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Отсутствие проверки сертификата</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="9">
		<button>Проверить сертификат</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Утечка ключей через логи</h2>
	<form method="GET" action="/a04">
		<input type="hidden" name="vuln" value="10">
		API Key: <input type="text" name="key" value="secret_key_123">
		<button>Использовать ключ</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	
	// Уязвимость 1: Хранение паролей в открытом виде
	if vuln == "1" {
		user := r.URL.Query().Get("user")
		passwords := map[string]string{
			"admin": "admin123",
			"user":  "password",
		}
		if pass, ok := passwords[user]; ok {
			w.Write([]byte(fmt.Sprintf("Пароль для %s: %s", user, pass)))
		}
		return
	}
	
	// Уязвимость 2: Использование MD5
	if vuln == "2" {
		pass := r.URL.Query().Get("pass")
		hash := md5.Sum([]byte(pass))
		w.Write([]byte(fmt.Sprintf("MD5 хеш: %x (НЕБЕЗОПАСНО! MD5 легко взломать)", hash)))
		return
	}
	
	// Уязвимость 3: Использование SHA1
	if vuln == "3" {
		pass := r.URL.Query().Get("pass")
		hash := sha1.Sum([]byte(pass))
		w.Write([]byte(fmt.Sprintf("SHA1 хеш: %x (НЕБЕЗОПАСНО! SHA1 устарел)", hash)))
		return
	}
	
	// Уязвимость 4: Слабый ключ шифрования
	if vuln == "4" {
		data := r.URL.Query().Get("data")
		key := "12345" // Слабый ключ
		// Простое XOR шифрование (небезопасно)
		encrypted := make([]byte, len(data))
		for i := range data {
			encrypted[i] = data[i] ^ key[i%len(key)]
		}
		w.Write([]byte(fmt.Sprintf("Зашифровано слабым ключом: %s", base64.StdEncoding.EncodeToString(encrypted))))
		return
	}
	
	// Уязвимость 5: Хранение ключей в коде
	if vuln == "5" {
		w.Write([]byte("API_KEY=sk_live_1234567890\nSECRET_KEY=secret123\nENCRYPTION_KEY=key456"))
		return
	}
	
	// Уязвимость 6: Использование HTTP вместо HTTPS
	if vuln == "6" {
		if r.TLS == nil {
			w.Write([]byte("Используется HTTP! Данные передаются в открытом виде!"))
		} else {
			w.Write([]byte("Используется HTTPS"))
		}
		return
	}
	
	// Уязвимость 7: Слабая генерация случайных чисел
	if vuln == "7" {
		// Используем время как "случайное" число (небезопасно)
		token := r.Header.Get("Date")
		w.Write([]byte(fmt.Sprintf("Токен сгенерирован: %s (используется время, небезопасно!)", token)))
		return
	}
	
	// Уязвимость 8: Небезопасный обмен ключами
	if vuln == "8" {
		w.Write([]byte("Ключ отправлен в открытом виде: shared_key=abc123"))
		return
	}
	
	// Уязвимость 9: Отсутствие проверки сертификата
	if vuln == "9" {
		w.Write([]byte("Сертификат не проверяется! Возможна MITM атака!"))
		return
	}
	
	// Уязвимость 10: Утечка ключей через логи
	if vuln == "10" {
		key := r.URL.Query().Get("key")
		// Логируем ключ (опасно!)
		fmt.Printf("API Key used: %s\n", key)
		w.Write([]byte(fmt.Sprintf("Ключ %s использован и записан в логи!", key)))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

