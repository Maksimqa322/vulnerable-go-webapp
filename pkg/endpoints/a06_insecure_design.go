package endpoints

import (
	"fmt"
	"net/http"
)

// A06:2025 - Insecure Design
// 10 уязвимостей разной сложности

func a06InsecureDesign(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A06: Insecure Design</h1>
	<h2>Уязвимость 1 (Легкая): Отсутствие rate limiting</h2>
	<form method="POST" action="/a06">
		<input type="hidden" name="vuln" value="1">
		<button>Отправить запрос (можно спамить!)</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Слабая валидация</h2>
	<form method="GET" action="/a06">
		<input type="hidden" name="vuln" value="2">
		Email: <input type="text" name="email" value="not-an-email">
		<button>Зарегистрироваться</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Отсутствие проверки CAPTCHA</h2>
	<form method="POST" action="/a06">
		<input type="hidden" name="vuln" value="3">
		<button>Создать аккаунт (без CAPTCHA!)</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Небезопасный дизайн API</h2>
	<form method="GET" action="/a06">
		<input type="hidden" name="vuln" value="4">
		Action: <input type="text" name="action" value="delete_all">
		<button>Выполнить действие</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Отсутствие проверки бизнес-логики</h2>
	<form method="POST" action="/a06">
		<input type="hidden" name="vuln" value="5">
		Amount: <input type="text" name="amount" value="-1000">
		<button>Перевести деньги</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Небезопасный дизайн паролей</h2>
	<form method="POST" action="/a06">
		<input type="hidden" name="vuln" value="6">
		Password: <input type="text" name="pass" value="123">
		<button>Установить пароль</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Отсутствие многофакторной аутентификации</h2>
	<form method="POST" action="/a06">
		<input type="hidden" name="vuln" value="7">
		Username: <input type="text" name="user" value="admin">
		Password: <input type="text" name="pass" value="admin">
		<button>Войти (без 2FA!)</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Небезопасный дизайн сессий</h2>
	<form method="GET" action="/a06">
		<input type="hidden" name="vuln" value="8">
		<button>Создать сессию (небезопасно!)</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Отсутствие аудита безопасности</h2>
	<form method="GET" action="/a06">
		<input type="hidden" name="vuln" value="9">
		<button>Показать настройки безопасности</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Небезопасный дизайн восстановления пароля</h2>
	<form method="POST" action="/a06">
		<input type="hidden" name="vuln" value="10">
		Email: <input type="text" name="email" value="victim@example.com">
		<button>Восстановить пароль</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	if r.Method == "POST" {
		vuln = r.FormValue("vuln")
	}
	
	// Уязвимость 1: Отсутствие rate limiting
	if vuln == "1" {
		// Нет ограничений на количество запросов
		w.Write([]byte("Запрос обработан! Можно отправлять тысячи запросов в секунду (DoS возможен!)"))
		return
	}
	
	// Уязвимость 2: Слабая валидация
	if vuln == "2" {
		email := r.URL.Query().Get("email")
		// Нет проверки формата email
		w.Write([]byte(fmt.Sprintf("Email '%s' принят без проверки!", email)))
		return
	}
	
	// Уязвимость 3: Отсутствие проверки CAPTCHA
	if vuln == "3" {
		// Нет CAPTCHA, можно автоматизировать
		w.Write([]byte("Аккаунт создан без проверки CAPTCHA! Боты могут создавать тысячи аккаунтов!"))
		return
	}
	
	// Уязвимость 4: Небезопасный дизайн API
	if vuln == "4" {
		action := r.URL.Query().Get("action")
		// Опасные действия доступны через простой параметр
		w.Write([]byte(fmt.Sprintf("Действие '%s' выполнено без дополнительных проверок!", action)))
		return
	}
	
	// Уязвимость 5: Отсутствие проверки бизнес-логики
	if vuln == "5" {
		amount := r.FormValue("amount")
		// Можно перевести отрицательную сумму или больше баланса
		w.Write([]byte(fmt.Sprintf("Перевод %s выполнен без проверки баланса и валидности суммы!", amount)))
		return
	}
	
	// Уязвимость 6: Небезопасный дизайн паролей
	if vuln == "6" {
		pass := r.FormValue("pass")
		// Нет требований к сложности пароля
		_ = pass // Используем переменную
		w.Write([]byte(fmt.Sprintf("Пароль '%s' установлен! Нет проверки на сложность!", pass)))
		return
	}
	
	// Уязвимость 7: Отсутствие многофакторной аутентификации
	if vuln == "7" {
		user := r.FormValue("user")
		_ = r.FormValue("pass") // Пароль не проверяется
		// Нет 2FA
		w.Write([]byte(fmt.Sprintf("Вход выполнен для %s без двухфакторной аутентификации!", user)))
		return
	}
	
	// Уязвимость 8: Небезопасный дизайн сессий
	if vuln == "8" {
		// Сессия не истекает, нет проверки IP
		w.Write([]byte("Сессия создана навсегда без проверки IP и времени жизни!"))
		return
	}
	
	// Уязвимость 9: Отсутствие аудита безопасности
	if vuln == "9" {
		w.Write([]byte("Аудит безопасности не настроен! Нет логирования критических действий!"))
		return
	}
	
	// Уязвимость 10: Небезопасный дизайн восстановления пароля
	if vuln == "10" {
		email := r.FormValue("email")
		// Пароль отправляется сразу без проверки владельца email
		w.Write([]byte(fmt.Sprintf("Новый пароль отправлен на %s без проверки владельца!", email)))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

