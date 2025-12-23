package endpoints

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// A10:2025 - Mishandling of Exceptional Conditions
// 10 реалистичных эндпоинтов

// Уязвимость 1: Раскрытие информации в ошибках
func apiV1UsersGet(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	
	// УЯЗВИМОСТЬ: Полная информация об ошибке раскрывается
	if userID == "" {
		w.Write([]byte(`Error: user_id parameter is required
Stack Trace:
  at UserService.getUser (UserService.java:142)
  at UserController.handleGet (UserController.java:67)
  at org.springframework.web.servlet.DispatcherServlet.doDispatch (DispatcherServlet.java:1040)
  
SQL Query: SELECT * FROM users WHERE id = NULL
Database: postgresql://prod-db.internal.company.com:5432/production
Connection Pool: 45/50 active
Memory Usage: 2.3GB / 4GB
Server: nginx/1.18.0
Framework: Spring Boot 2.5.0`))
		return
	}
	
	sendJSON(w, map[string]interface{}{
		"status": "success",
		"user": map[string]string{
			"id":    userID,
			"name":  "John Doe",
			"email": "john@example.com",
		},
	})
}

// Уязвимость 2: Отсутствие обработки ошибок
func apiV1Calculate(w http.ResponseWriter, r *http.Request) {
	numStr := r.URL.Query().Get("number")
	
	// УЯЗВИМОСТЬ: Нет проверки на ошибку парсинга
	num, _ := strconv.Atoi(numStr)
	result := 100 / num
	
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"result":  result,
		"warning": "Division by zero may cause panic!",
	})
}

// Уязвимость 3: Чувствительные данные в логах ошибок
func apiV1DatabaseQuery(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	
	// УЯЗВИМОСТЬ: Полная информация об ошибке с чувствительными данными логируется
	fmt.Printf(`[ERROR] Database query failed
Query: %s
Database: postgresql://admin:SuperSecret123@prod-db:5432/production
Stack: main.go:42
Connection: 192.168.1.100:5432
`, query)
	
	sendJSON(w, map[string]interface{}{
		"status":  "error",
		"message": "Query failed (sensitive data logged!)",
	})
}

// Уязвимость 4: Stack trace в ответе
func apiV1Process(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Полный stack trace показывается пользователю
	w.Write([]byte(`Panic: runtime error: invalid memory address or nil pointer dereference

goroutine 1 [running]:
main.processRequest(0xc000010200)
	/home/user/app/main.go:42 +0x1a5
main.handleHTTP(0xc000010200)
	/home/user/app/main.go:67 +0x8f
net/http.HandlerFunc.ServeHTTP(0x123456, 0x789abc)
	/usr/local/go/src/net/http/server.go:2042 +0x44
net/http.(*ServeMux).ServeHTTP(0xdef456, 0x789abc, 0xc000010200)
	/usr/local/go/src/net/http/server.go:2417 +0x1a5`))
}

// Уязвимость 5: Отсутствие валидации входных данных
func apiV1Transfer(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		amount := r.FormValue("amount")
		
		// УЯЗВИМОСТЬ: Нет проверки на отрицательные значения
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Transfer of %s completed (no validation!)", amount),
			"warning": "Negative amounts allowed",
		})
		return
	}
	
	html := renderPage("Transfer", `
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

// Уязвимость 6: Неправильная обработка исключений
func apiV1FileRead(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	
	// УЯЗВИМОСТЬ: Ошибка обрабатывается, но информация раскрывается
	w.Write([]byte(fmt.Sprintf(`Error reading file: %s
Reason: permission denied
File exists: true
File path: /var/www/app/data/%s
System: Linux kernel 5.15.0
User: www-data
UID: 33
GID: 33
Permissions: 644
Owner: root
`, file, file)))
}

// Уязвимость 7: Race condition в обработке ошибок
func apiV1Concurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		action := r.FormValue("action")
		
		// УЯЗВИМОСТЬ: Ошибки обрабатываются небезопасно в конкурентной среде
		time.Sleep(100 * time.Millisecond) // Имитация обработки
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Action '%s' processed (not thread-safe!)", action),
			"warning": "Race condition possible",
		})
		return
	}
	
	html := renderPage("Concurrent Action", `
		<div class="card">
			<h2>Execute Action</h2>
			<form method="POST">
				<div class="form-group">
					<label>Action</label>
					<input type="text" name="action" value="transfer">
				</div>
				<button type="submit" class="btn">Execute</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 8: Утечка информации через таймауты
func apiV1UserCheck(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// УЯЗВИМОСТЬ: Разное время ответа раскрывает информацию
	if username == "admin" {
		time.Sleep(2 * time.Second) // Долгий ответ означает, что пользователь существует
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "User exists (determined by response time!)",
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "User not found",
		})
	}
}

// Уязвимость 9: Небезопасная обработка null значений
func apiV1DataProcess(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	
	// УЯЗВИМОСТЬ: Нет проверки на null/пустое значение
	if data == "" {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Data is null, but processing continues (may cause panic!)",
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Data processed: %s", data),
		})
	}
}

// Уязвимость 10: Отсутствие graceful degradation
func apiV1ServiceStatus(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: При ошибке сервис полностью падает
	sendJSON(w, map[string]interface{}{
		"status":  "error",
		"message": "Database connection failed! Entire service unavailable (no graceful degradation!)",
		"services": map[string]string{
			"database": "down",
			"api":      "down",
			"cache":    "down",
		},
		"warning": "No fallback mechanisms",
	})
}

