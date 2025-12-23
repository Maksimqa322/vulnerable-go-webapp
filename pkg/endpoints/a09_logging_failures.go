package endpoints

import (
	"fmt"
	"log"
	"net/http"
)

// A09:2025 - Security Logging and Alerting Failures
// 10 уязвимостей разной сложности

func a09LoggingFailures(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A09: Security Logging and Alerting Failures</h1>
	<h2>Уязвимость 1 (Легкая): Отсутствие логирования</h2>
	<form method="POST" action="/a09">
		<input type="hidden" name="vuln" value="1">
		Action: <input type="text" name="action" value="delete_user">
		<button>Выполнить действие</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Логирование чувствительных данных</h2>
	<form method="POST" action="/a09">
		<input type="hidden" name="vuln" value="2">
		Password: <input type="text" name="pass" value="secret123">
		<button>Войти (пароль в логах!)</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Отсутствие мониторинга</h2>
	<form method="GET" action="/a09">
		<input type="hidden" name="vuln" value="3">
		<button>Показать настройки мониторинга</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Недостаточное логирование</h2>
	<form method="POST" action="/a09">
		<input type="hidden" name="vuln" value="4">
		User ID: <input type="text" name="user_id" value="1">
		<button>Удалить пользователя</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Отсутствие алертов</h2>
	<form method="POST" action="/a09">
		<input type="hidden" name="vuln" value="5">
		Failed logins: <input type="text" name="count" value="1000">
		<button>Попытка входа (нет алерта!)</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Логи в открытом доступе</h2>
	<a href="/logs/access.log">Показать логи доступа</a>
	
	<h2>Уязвимость 7 (Сложная): Отсутствие корреляции событий</h2>
	<form method="GET" action="/a09">
		<input type="hidden" name="vuln" value="7">
		<button>Показать события</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Недостаточная детализация логов</h2>
	<form method="POST" action="/a09">
		<input type="hidden" name="vuln" value="8">
		Action: <input type="text" name="action" value="transfer">
		Amount: <input type="text" name="amount" value="10000">
		<button>Выполнить</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Отсутствие анализа логов</h2>
	<form method="GET" action="/a09">
		<input type="hidden" name="vuln" value="9">
		<button>Показать анализ</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Небезопасное хранение логов</h2>
	<form method="GET" action="/a09">
		<input type="hidden" name="vuln" value="10">
		<button>Показать настройки хранения</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	if r.Method == "POST" {
		vuln = r.FormValue("vuln")
	}
	
	// Уязвимость 1: Отсутствие логирования
	if vuln == "1" {
		action := r.FormValue("action")
		// Критические действия не логируются
		w.Write([]byte(fmt.Sprintf("Действие '%s' выполнено без логирования!", action)))
		return
	}
	
	// Уязвимость 2: Логирование чувствительных данных
	if vuln == "2" {
		pass := r.FormValue("pass")
		// Пароль логируется в открытом виде
		log.Printf("Login attempt with password: %s", pass)
		w.Write([]byte(fmt.Sprintf("Пароль '%s' записан в логи в открытом виде!", pass)))
		return
	}
	
	// Уязвимость 3: Отсутствие мониторинга
	if vuln == "3" {
		w.Write([]byte("Мониторинг не настроен! Нет отслеживания подозрительной активности!"))
		return
	}
	
	// Уязвимость 4: Недостаточное логирование
	if vuln == "4" {
		userID := r.FormValue("user_id")
		// Логируется только ID, без IP, времени, пользователя
		log.Printf("User deleted: %s", userID)
		w.Write([]byte(fmt.Sprintf("Пользователь %s удален, но логи недостаточны (нет IP, времени, исполнителя)!", userID)))
		return
	}
	
	// Уязвимость 5: Отсутствие алертов
	if vuln == "5" {
		count := r.FormValue("count")
		// Нет алерта при множественных неудачных попытках
		w.Write([]byte(fmt.Sprintf("%s неудачных попыток входа, но алерт не отправлен!", count)))
		return
	}
	
	// Уязвимость 6: Логи в открытом доступе
	if r.URL.Path == "/logs/access.log" {
		w.Write([]byte("2024-01-01 10:00:00 GET /admin - 200\n2024-01-01 10:01:00 POST /login user=admin pass=admin123 - 200\n2024-01-01 10:02:00 DELETE /users/5 - 200"))
		return
	}
	
	// Уязвимость 7: Отсутствие корреляции событий
	if vuln == "7" {
		w.Write([]byte("События не коррелируются! Невозможно отследить цепочку атак!"))
		return
	}
	
	// Уязвимость 8: Недостаточная детализация логов
	if vuln == "8" {
		action := r.FormValue("action")
		amount := r.FormValue("amount")
		// Логируется только действие, без деталей
		log.Printf("Action: %s", action)
		w.Write([]byte(fmt.Sprintf("Действие '%s' на сумму %s выполнено, но в логах нет деталей!", action, amount)))
		return
	}
	
	// Уязвимость 9: Отсутствие анализа логов
	if vuln == "9" {
		w.Write([]byte("Анализ логов не выполняется! Подозрительная активность не обнаруживается!"))
		return
	}
	
	// Уязвимость 10: Небезопасное хранение логов
	if vuln == "10" {
		w.Write([]byte("Логи хранятся в открытом виде без шифрования! Доступ: /logs/"))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

