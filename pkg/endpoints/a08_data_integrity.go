package endpoints

import (
	"fmt"
	"net/http"
)

// A08:2025 - Software or Data Integrity Failures
// 10 уязвимостей разной сложности

func a08DataIntegrity(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A08: Software or Data Integrity Failures</h1>
	<h2>Уязвимость 1 (Легкая): Отсутствие проверки подписи</h2>
	<form method="POST" action="/a08">
		<input type="hidden" name="vuln" value="1">
		File: <input type="text" name="file" value="update.exe">
		<button>Загрузить файл</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Небезопасное обновление</h2>
	<form method="GET" action="/a08">
		<input type="hidden" name="vuln" value="2">
		Version: <input type="text" name="version" value="2.0.0">
		<button>Обновить</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Отсутствие проверки целостности данных</h2>
	<form method="POST" action="/a08">
		<input type="hidden" name="vuln" value="3">
		Data: <input type="text" name="data" value="important_data">
		<button>Сохранить данные</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Небезопасная загрузка зависимостей</h2>
	<form method="GET" action="/a08">
		<input type="hidden" name="vuln" value="4">
		Package: <input type="text" name="package" value="github.com/evil/package">
		<button>Установить пакет</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Отсутствие проверки checksum</h2>
	<form method="POST" action="/a08">
		<input type="hidden" name="vuln" value="5">
		File: <input type="text" name="file" value="app.zip">
		<button>Загрузить файл</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Небезопасный CI/CD pipeline</h2>
	<form method="GET" action="/a08">
		<input type="hidden" name="vuln" value="6">
		<button>Показать настройки CI/CD</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Подмена репозитория</h2>
	<form method="GET" action="/a08">
		<input type="hidden" name="vuln" value="7">
		Repo: <input type="text" name="repo" value="github.com/company/repo">
		<button>Клонировать репозиторий</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Отсутствие проверки подписи кода</h2>
	<form method="POST" action="/a08">
		<input type="hidden" name="vuln" value="8">
		Code: <input type="text" name="code" value="malicious_code">
		<button>Выполнить код</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Небезопасная цепочка доверия</h2>
	<form method="GET" action="/a08">
		<input type="hidden" name="vuln" value="9">
		<button>Показать цепочку доверия</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Отсутствие проверки времени модификации</h2>
	<form method="GET" action="/a08">
		<input type="hidden" name="vuln" value="10">
		File: <input type="text" name="file" value="config.json">
		<button>Проверить файл</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	if r.Method == "POST" {
		vuln = r.FormValue("vuln")
	}
	
	// Уязвимость 1: Отсутствие проверки подписи
	if vuln == "1" {
		file := r.FormValue("file")
		// Файл загружается без проверки подписи
		w.Write([]byte(fmt.Sprintf("Файл %s загружен без проверки цифровой подписи!", file)))
		return
	}
	
	// Уязвимость 2: Небезопасное обновление
	if vuln == "2" {
		version := r.URL.Query().Get("version")
		// Обновление без проверки подписи
		w.Write([]byte(fmt.Sprintf("Обновление до версии %s выполнено без проверки подписи разработчика!", version)))
		return
	}
	
	// Уязвимость 3: Отсутствие проверки целостности данных
	if vuln == "3" {
		data := r.FormValue("data")
		// Данные сохраняются без checksum
		w.Write([]byte(fmt.Sprintf("Данные '%s' сохранены без проверки целостности (можно изменить!)", data)))
		return
	}
	
	// Уязвимость 4: Небезопасная загрузка зависимостей
	if vuln == "4" {
		packageName := r.URL.Query().Get("package")
		// Пакет устанавливается без проверки
		w.Write([]byte(fmt.Sprintf("Пакет %s установлен без проверки подписи и целостности!", packageName)))
		return
	}
	
	// Уязвимость 5: Отсутствие проверки checksum
	if vuln == "5" {
		file := r.FormValue("file")
		// Файл загружается без проверки SHA256/MD5
		w.Write([]byte(fmt.Sprintf("Файл %s загружен без проверки checksum (может быть изменен!)", file)))
		return
	}
	
	// Уязвимость 6: Небезопасный CI/CD pipeline
	if vuln == "6" {
		w.Write([]byte("CI/CD pipeline настроен без проверки подписи кода! Можно внедрить вредоносный код!"))
		return
	}
	
	// Уязвимость 7: Подмена репозитория
	if vuln == "7" {
		repo := r.URL.Query().Get("repo")
		// Репозиторий клонируется без проверки
		w.Write([]byte(fmt.Sprintf("Репозиторий %s клонирован без проверки подписи коммитов!", repo)))
		return
	}
	
	// Уязвимость 8: Отсутствие проверки подписи кода
	if vuln == "8" {
		code := r.FormValue("code")
		// Код выполняется без проверки подписи
		w.Write([]byte(fmt.Sprintf("Код '%s' выполнен без проверки цифровой подписи!", code)))
		return
	}
	
	// Уязвимость 9: Небезопасная цепочка доверия
	if vuln == "9" {
		w.Write([]byte("Цепочка доверия не проверяется! Можно использовать поддельные сертификаты!"))
		return
	}
	
	// Уязвимость 10: Отсутствие проверки времени модификации
	if vuln == "10" {
		file := r.URL.Query().Get("file")
		// Нет проверки времени модификации файла
		w.Write([]byte(fmt.Sprintf("Файл %s проверен без учета времени модификации (можно откатить!)", file)))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

