package endpoints

import (
	"fmt"
	"net/http"
)

// A07:2025 - Authentication Failures
// 10 уязвимостей разной сложности

var users = map[string]string{
	"admin": "admin",
	"user":  "password",
}

func a07AuthenticationFailures(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A07: Authentication Failures</h1>
	<h2>Уязвимость 1 (Легкая): Слабые пароли по умолчанию</h2>
	<form method="POST" action="/a07">
		<input type="hidden" name="vuln" value="1">
		Username: <input type="text" name="user" value="admin">
		Password: <input type="text" name="pass" value="admin">
		<button>Войти</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Отсутствие блокировки после неудачных попыток</h2>
	<form method="POST" action="/a07">
		<input type="hidden" name="vuln" value="2">
		Username: <input type="text" name="user" value="admin">
		Password: <input type="text" name="pass" value="wrong">
		<button>Попробовать войти (можно брутфорсить!)</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Пароли в открытом виде</h2>
	<form method="GET" action="/a07">
		<input type="hidden" name="vuln" value="3">
		Username: <input type="text" name="user" value="admin">
		<button>Показать пароль</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Слабая проверка сессии</h2>
	<form method="GET" action="/a07">
		<input type="hidden" name="vuln" value="4">
		Session: <input type="text" name="session" value="any_string">
		<button>Проверить сессию</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Отсутствие проверки времени сессии</h2>
	<form method="GET" action="/a07">
		<input type="hidden" name="vuln" value="5">
		<button>Проверить сессию (никогда не истекает!)</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Небезопасное восстановление пароля</h2>
	<form method="POST" action="/a07">
		<input type="hidden" name="vuln" value="6">
		Username: <input type="text" name="user" value="admin">
		<button>Восстановить пароль</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Отсутствие многофакторной аутентификации</h2>
	<form method="POST" action="/a07">
		<input type="hidden" name="vuln" value="7">
		Username: <input type="text" name="user" value="admin">
		Password: <input type="text" name="pass" value="admin">
		<button>Войти (без 2FA!)</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Подделка сессий</h2>
	<form method="GET" action="/a07">
		<input type="hidden" name="vuln" value="8">
		Session ID: <input type="text" name="sid" value="admin_session">
		<button>Использовать сессию</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Отсутствие проверки IP адреса</h2>
	<form method="GET" action="/a07">
		<input type="hidden" name="vuln" value="9">
		<button>Проверить сессию (IP не проверяется!)</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Утечка учетных данных</h2>
	<form method="POST" action="/a07">
		<input type="hidden" name="vuln" value="10">
		Username: <input type="text" name="user" value="admin">
		Password: <input type="text" name="pass" value="admin">
		<button>Войти (логируются в открытом виде!)</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	if r.Method == "POST" {
		vuln = r.FormValue("vuln")
	}
	
	// Уязвимость 1: Слабые пароли по умолчанию
	if vuln == "1" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		if users[user] == pass {
			w.Write([]byte(fmt.Sprintf("Вход выполнен! Пароль по умолчанию '%s' не изменен!", pass)))
		} else {
			w.Write([]byte("Неверный пароль"))
		}
		return
	}
	
	// Уязвимость 2: Отсутствие блокировки после неудачных попыток
	if vuln == "2" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		// Нет блокировки, можно брутфорсить
		if users[user] == pass {
			w.Write([]byte("Вход выполнен!"))
		} else {
			w.Write([]byte("Неверный пароль! Можно пробовать бесконечно!"))
		}
		return
	}
	
	// Уязвимость 3: Пароли в открытом виде
	if vuln == "3" {
		user := r.URL.Query().Get("user")
		if pass, ok := users[user]; ok {
			w.Write([]byte(fmt.Sprintf("Пароль для %s: %s (хранится в открытом виде!)", user, pass)))
		}
		return
	}
	
	// Уязвимость 4: Слабая проверка сессии
	if vuln == "4" {
		session := r.URL.Query().Get("session")
		// Любая строка принимается как валидная сессия
		if len(session) > 0 {
			w.Write([]byte(fmt.Sprintf("Сессия '%s' принята без проверки!", session)))
		}
		return
	}
	
	// Уязвимость 5: Отсутствие проверки времени сессии
	if vuln == "5" {
		// Сессия никогда не истекает
		w.Write([]byte("Сессия активна навсегда! Нет проверки времени жизни!"))
		return
	}
	
	// Уязвимость 6: Небезопасное восстановление пароля
	if vuln == "6" {
		user := r.FormValue("user")
		// Пароль отправляется сразу без проверки
		if pass, ok := users[user]; ok {
			w.Write([]byte(fmt.Sprintf("Новый пароль для %s отправлен на email без проверки владельца: %s", user, pass)))
		}
		return
	}
	
	// Уязвимость 7: Отсутствие многофакторной аутентификации
	if vuln == "7" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		if users[user] == pass {
			w.Write([]byte(fmt.Sprintf("Вход выполнен для %s без двухфакторной аутентификации!", user)))
		}
		return
	}
	
	// Уязвимость 8: Подделка сессий
	if vuln == "8" {
		sid := r.URL.Query().Get("sid")
		// Можно подделать сессию
		if sid == "admin_session" {
			w.Write([]byte("Админ сессия подделана! Доступ получен!"))
		} else {
			w.Write([]byte("Сессия не подходит"))
		}
		return
	}
	
	// Уязвимость 9: Отсутствие проверки IP адреса
	if vuln == "9" {
		// IP не проверяется, можно использовать сессию с другого IP
		w.Write([]byte("Сессия валидна с любого IP адреса!"))
		return
	}
	
	// Уязвимость 10: Утечка учетных данных
	if vuln == "10" {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		// Логируем пароль в открытом виде
		fmt.Printf("Login attempt: user=%s, password=%s\n", user, pass)
		w.Write([]byte(fmt.Sprintf("Учетные данные логируются в открытом виде! user=%s, pass=%s", user, pass)))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

