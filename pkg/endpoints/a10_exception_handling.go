package endpoints

import (
	"fmt"
	"net/http"
	"strconv"
)

// A10:2025 - Mishandling of Exceptional Conditions
// 10 уязвимостей разной сложности

func a10ExceptionHandling(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A10: Mishandling of Exceptional Conditions</h1>
	<h2>Уязвимость 1 (Легкая): Раскрытие информации в ошибках</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="1">
		User ID: <input type="text" name="id" value="999999">
		<button>Получить пользователя</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Отсутствие обработки ошибок</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="2">
		Number: <input type="text" name="num" value="abc">
		<button>Разделить на число</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Небезопасное логирование ошибок</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="3">
		Query: <input type="text" name="query" value="SELECT * FROM users">
		<button>Выполнить запрос</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Stack trace в ответе</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="4">
		<button>Вызвать ошибку</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Отсутствие валидации входных данных</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="5">
		Amount: <input type="text" name="amount" value="-1000">
		<button>Перевести деньги</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Неправильная обработка исключений</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="6">
		File: <input type="text" name="file" value="/etc/passwd">
		<button>Прочитать файл</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Race condition в обработке ошибок</h2>
	<form method="POST" action="/a10">
		<input type="hidden" name="vuln" value="7">
		Action: <input type="text" name="action" value="transfer">
		<button>Выполнить</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Утечка информации через таймауты</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="8">
		Username: <input type="text" name="user" value="admin">
		<button>Проверить пользователя</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Небезопасная обработка null значений</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="9">
		Data: <input type="text" name="data" value="">
		<button>Обработать данные</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Отсутствие graceful degradation</h2>
	<form method="GET" action="/a10">
		<input type="hidden" name="vuln" value="10">
		<button>Проверить сервис</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	if r.Method == "POST" {
		vuln = r.FormValue("vuln")
	}
	
	// Уязвимость 1: Раскрытие информации в ошибках
	if vuln == "1" {
		id := r.URL.Query().Get("id")
		// Показываем полную информацию об ошибке
		w.Write([]byte(fmt.Sprintf("Ошибка: пользователь с ID=%s не найден в таблице users в базе данных postgresql на сервере db.internal:5432. SQL запрос: SELECT * FROM users WHERE id=%s", id, id)))
		return
	}
	
	// Уязвимость 2: Отсутствие обработки ошибок
	if vuln == "2" {
		numStr := r.URL.Query().Get("num")
		// Нет проверки на ошибку парсинга
		num, _ := strconv.Atoi(numStr)
		result := 100 / num
		w.Write([]byte(fmt.Sprintf("Результат: %d (может вызвать панику!)", result)))
		return
	}
	
	// Уязвимость 3: Небезопасное логирование ошибок
	if vuln == "3" {
		query := r.URL.Query().Get("query")
		// Логируем полный запрос с ошибкой
		fmt.Printf("SQL Error: %s\nStack: main.go:42\nDatabase: postgresql://admin:pass@db:5432/prod", query)
		w.Write([]byte(fmt.Sprintf("Ошибка SQL запроса '%s' залогирована с полной информацией!", query)))
		return
	}
	
	// Уязвимость 4: Stack trace в ответе
	if vuln == "4" {
		// Показываем полный stack trace
		w.Write([]byte("Panic: runtime error: invalid memory address\n\ngoroutine 1 [running]:\nmain.handleRequest(0x123456)\n\t/home/user/app/main.go:42\nmain.main()\n\t/home/user/app/main.go:15"))
		return
	}
	
	// Уязвимость 5: Отсутствие валидации входных данных
	if vuln == "5" {
		amount := r.URL.Query().Get("amount")
		// Нет проверки на отрицательные значения
		w.Write([]byte(fmt.Sprintf("Перевод %s выполнен без проверки валидности!", amount)))
		return
	}
	
	// Уязвимость 6: Неправильная обработка исключений
	if vuln == "6" {
		file := r.URL.Query().Get("file")
		// Ошибка обрабатывается, но информация раскрывается
		w.Write([]byte(fmt.Sprintf("Ошибка чтения файла %s: permission denied. Файл существует, но нет доступа. Система: Linux, пользователь: www-data", file)))
		return
	}
	
	// Уязвимость 7: Race condition в обработке ошибок
	if vuln == "7" {
		action := r.FormValue("action")
		// Ошибки обрабатываются небезопасно в конкурентной среде
		w.Write([]byte(fmt.Sprintf("Действие '%s' выполнено, но обработка ошибок не thread-safe!", action)))
		return
	}
	
	// Уязвимость 8: Утечка информации через таймауты
	if vuln == "8" {
		user := r.URL.Query().Get("user")
		// Разное время ответа раскрывает информацию
		if user == "admin" {
			// Долгий ответ означает, что пользователь существует
			w.Write([]byte("Пользователь существует (определено по времени ответа!)"))
		} else {
			w.Write([]byte("Пользователь не найден"))
		}
		return
	}
	
	// Уязвимость 9: Небезопасная обработка null значений
	if vuln == "9" {
		data := r.URL.Query().Get("data")
		// Нет проверки на null/пустое значение
		if data == "" {
			w.Write([]byte("Ошибка: данные null, но обработка продолжается (может вызвать панику!)"))
		} else {
			w.Write([]byte(fmt.Sprintf("Данные обработаны: %s", data)))
		}
		return
	}
	
	// Уязвимость 10: Отсутствие graceful degradation
	if vuln == "10" {
		// При ошибке сервис полностью падает
		w.Write([]byte("Ошибка подключения к базе данных! Весь сервис недоступен (нет graceful degradation!)"))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

