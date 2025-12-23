package endpoints

import (
	"fmt"
	"net/http"
)

// A02:2025 - Security Misconfiguration
// 10 реалистичных эндпоинтов

// Уязвимость 1: Открытый .env файл
func apiV1ConfigEnv(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: .env файл доступен через веб-сервер
	w.Write([]byte(`DATABASE_URL=postgresql://admin:SuperSecret123@db.prod:5432/production
REDIS_URL=redis://admin:RedisPass456@redis.prod:6379
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51Hqw2LKD8vqX8Z4EXAMPLE
JWT_SECRET=my-super-secret-jwt-key-12345
API_KEY=prod_api_key_abcdef123456`))
}

// Уязвимость 2: Отладочная информация в production
func apiV1UsersSearchDebug(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	// УЯЗВИМОСТЬ: Показываем полный stack trace и SQL запрос
	if query == "" {
		w.Write([]byte(`Error: Empty query parameter
Stack Trace:
  at UserService.searchUsers (UserService.java:142)
  at UserController.handleSearch (UserController.java:67)
  at org.springframework.web.servlet.DispatcherServlet.doDispatch (DispatcherServlet.java:1040)
  
SQL Query: SELECT * FROM users WHERE name LIKE '%' OR '1'='1'
Database: postgresql://prod-db.internal:5432
Connection Pool: 45/50 active
Memory Usage: 2.3GB / 4GB`))
		return
	}
	
	sendJSON(w, map[string]interface{}{
		"status": "success",
		"results": []string{"user1", "user2"},
	})
}

// Уязвимость 3: Открытый доступ к метрикам
func apiV1Metrics(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Prometheus метрики доступны без аутентификации
	w.Write([]byte(`# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 123456
http_requests_total{method="POST",status="200"} 45678
http_requests_total{method="GET",status="404"} 1234

# HELP database_connections Database connection pool
# TYPE database_connections gauge
database_connections{state="active"} 45
database_connections{state="idle"} 5

# HELP api_keys_used API keys usage
api_keys_used{key="sk_live_abc123"} 1234
api_keys_used{key="sk_live_def456"} 5678`))
}

// Уязвимость 4: Открытый Git репозиторий
func apiV1GitConfig(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: .git директория доступна через веб-сервер
	w.Write([]byte(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
[remote "origin"]
	url = https://github.com/company/production-app.git
	branch = main
[user]
	name = Production Deploy
	email = deploy@company.com`))
}

// Уязвимость 5: Слабая конфигурация CORS
func apiV1ApiData(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: CORS разрешен для всех доменов
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	
	sendJSON(w, map[string]interface{}{
		"status": "success",
		"data": map[string]string{
			"user_id": "123",
			"api_key": "sk_live_1234567890",
			"token":   "jwt_token_abc123",
		},
	})
}

// Уязвимость 6: Версия и технологии в заголовках
func apiV1Health(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Раскрываем версии технологий
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("X-Powered-By", "Express/4.17.1")
	w.Header().Set("X-Framework", "Spring Boot 2.5.0")
	w.Header().Set("X-Database", "PostgreSQL 13.2")
	w.Header().Set("X-Redis", "6.2.0")
	
	sendJSON(w, map[string]interface{}{
		"status": "healthy",
		"version": "1.2.3",
		"build": "2024-01-15T10:30:00Z",
	})
}

// Уязвимость 7: Небезопасные настройки сессий
func apiV1AuthSession(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Сессия без HttpOnly и Secure флагов
	w.Header().Set("Set-Cookie", "session=abc123def456; Path=/")
	w.Header().Set("Set-Cookie", "user_id=123; Path=/")
	
	sendJSON(w, map[string]interface{}{
		"status": "success",
		"session": "abc123def456",
	})
}

// Уязвимость 8: Открытый доступ к backup файлам
func apiV1Backup(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	
	// УЯЗВИМОСТЬ: Backup файлы доступны через веб
	if file == "database_backup_2024.sql" {
		w.Write([]byte("-- Database backup\n-- Contains user passwords, API keys, etc.\nINSERT INTO users VALUES (1, 'admin', 'password123', 'admin@company.com');"))
	} else {
		w.Write([]byte(fmt.Sprintf("Backup file: %s\nLocation: /backups/%s", file, file)))
	}
}

// Уязвимость 9: Открытый доступ к логам
func apiV1Logs(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Логи доступны без аутентификации
	w.Write([]byte(`2024-01-15 10:30:15 [INFO] User login: admin@company.com
2024-01-15 10:30:20 [INFO] API call: GET /api/v1/users/123
2024-01-15 10:30:25 [ERROR] Database connection failed: postgresql://admin:password@db:5432
2024-01-15 10:30:30 [INFO] Payment processed: amount=1000, user_id=123
2024-01-15 10:30:35 [DEBUG] JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`))
}

// Уязвимость 10: Конфигурация базы данных в открытом виде
func apiV1ConfigDatabase(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Конфигурация БД доступна через API
	sendJSON(w, map[string]interface{}{
		"database": map[string]string{
			"host":     "prod-db.internal.company.com",
			"port":     "5432",
			"database": "production",
			"username": "db_admin",
			"password": "SuperSecretDBPassword123",
			"ssl_mode": "disable",
		},
		"redis": map[string]string{
			"host": "redis-prod.internal",
			"port": "6379",
			"auth": "RedisPassword456",
		},
	})
}

