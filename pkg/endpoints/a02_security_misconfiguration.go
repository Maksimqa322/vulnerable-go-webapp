package endpoints

import (
	"fmt"
	"net/http"
	"os"
)

// A02:2025 - Security Misconfiguration
// 10 уязвимостей разной сложности

func a02SecurityMisconfiguration(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A02: Security Misconfiguration</h1>
	<h2>Уязвимость 1 (Легкая): Открытый .env файл</h2>
	<a href="/.env">Показать .env</a>
	
	<h2>Уязвимость 2 (Легкая): Отладочная информация</h2>
	<form method="GET" action="/a02">
		<input type="hidden" name="vuln" value="2">
		ID: <input type="text" name="id" value="1">
		<button>Получить данные</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Открытый Git репозиторий</h2>
	<a href="/.git/config">Показать .git/config</a>
	
	<h2>Уязвимость 4 (Средняя): Слабая конфигурация CORS</h2>
	<form method="GET" action="/a02">
		<input type="hidden" name="vuln" value="4">
		<button>Проверить CORS</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Открытые директории</h2>
	<a href="/backup/">Показать backup директорию</a>
	
	<h2>Уязвимость 6 (Средняя): Версия в заголовках</h2>
	<form method="GET" action="/a02">
		<input type="hidden" name="vuln" value="6">
		<button>Показать заголовки</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Небезопасные настройки сессий</h2>
	<form method="GET" action="/a02">
		<input type="hidden" name="vuln" value="7">
		<button>Создать сессию</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Неправильная настройка HTTPS</h2>
	<form method="GET" action="/a02">
		<input type="hidden" name="vuln" value="8">
		<button>Проверить HTTPS</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Открытый доступ к метрикам</h2>
	<a href="/metrics">Показать метрики</a>
	
	<h2>Уязвимость 10 (Сложная): Небезопасная конфигурация базы данных</h2>
	<form method="GET" action="/a02">
		<input type="hidden" name="vuln" value="10">
		<button>Показать конфигурацию БД</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	
	// Уязвимость 1: Открытый .env файл
	if r.URL.Path == "/.env" {
		w.Write([]byte("DB_PASSWORD=secret123\nAPI_KEY=key12345\nADMIN_TOKEN=admin_token"))
		return
	}
	
	// Уязвимость 2: Отладочная информация
	if vuln == "2" {
		id := r.URL.Query().Get("id")
		// Показываем полный стек ошибки
		w.Write([]byte(fmt.Sprintf("Ошибка получения данных для ID=%s\nStack trace:\nmain.go:42\nendpoints.go:15\nSQL: SELECT * FROM users WHERE id=%s", id, id)))
		return
	}
	
	// Уязвимость 3: Открытый Git репозиторий
	if r.URL.Path == "/.git/config" {
		w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/company/secret-repo.git"))
		return
	}
	
	// Уязвимость 4: Слабая конфигурация CORS
	if vuln == "4" {
		// Разрешаем всем доменам
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Write([]byte("CORS разрешен для всех доменов"))
		return
	}
	
	// Уязвимость 5: Открытые директории
	if r.URL.Path == "/backup/" {
		w.Write([]byte("backup_2024.db\nbackup_2023.db\npasswords.txt\nconfig.old"))
		return
	}
	
	// Уязвимость 6: Версия в заголовках
	if vuln == "6" {
		w.Header().Set("Server", "Go/1.24.9")
		w.Header().Set("X-Powered-By", "vulnWeb/1.0.0")
		w.Header().Set("X-Framework", "custom-framework v2.1")
		w.Write([]byte("Заголовки отправлены"))
		return
	}
	
	// Уязвимость 7: Небезопасные настройки сессий
	if vuln == "7" {
		// Сессия без HttpOnly и Secure флагов
		w.Header().Set("Set-Cookie", "session=abc123; Path=/")
		w.Write([]byte("Сессия создана (небезопасно)"))
		return
	}
	
	// Уязвимость 8: Неправильная настройка HTTPS
	if vuln == "8" {
		// Нет HSTS заголовка
		w.Write([]byte("HTTPS не настроен правильно. Нет HSTS заголовка."))
		return
	}
	
	// Уязвимость 9: Открытый доступ к метрикам
	if r.URL.Path == "/metrics" {
		w.Write([]byte("http_requests_total 12345\nhttp_errors_total 12\nactive_connections 5\nmemory_usage_bytes 1048576"))
		return
	}
	
	// Уязвимость 10: Небезопасная конфигурация базы данных
	if vuln == "10" {
		// Показываем конфигурацию БД
		w.Write([]byte("DB_HOST=localhost\nDB_PORT=5432\nDB_USER=admin\nDB_NAME=production\nDB_SSL_MODE=disable"))
		return
	}
	
	// Показываем файлы системы (опасно!)
	if r.URL.Query().Get("file") != "" {
		file := r.URL.Query().Get("file")
		content, _ := os.ReadFile(file)
		w.Write(content)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

