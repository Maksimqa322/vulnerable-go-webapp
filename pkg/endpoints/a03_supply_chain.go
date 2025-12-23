package endpoints

import (
	"fmt"
	"net/http"
	"os/exec"
)

// A03:2025 - Software Supply Chain Failures
// 10 уязвимостей разной сложности

func a03SupplyChain(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A03: Software Supply Chain Failures</h1>
	<h2>Уязвимость 1 (Легкая): Использование устаревших библиотек</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="1">
		<button>Показать версии библиотек</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Загрузка зависимостей без проверки</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="2">
		Package: <input type="text" name="package" value="github.com/evil/package">
		<button>Установить пакет</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Использование небезопасных источников</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="3">
		URL: <input type="text" name="url" value="http://untrusted.com/script.js">
		<button>Загрузить скрипт</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Отсутствие проверки целостности</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="4">
		File: <input type="text" name="file" value="update.zip">
		<button>Загрузить файл</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Выполнение произвольного кода</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="5">
		Command: <input type="text" name="cmd" value="ls">
		<button>Выполнить команду</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Небезопасное обновление</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="6">
		Version: <input type="text" name="version" value="1.0.0">
		<button>Обновить</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): Подмена зависимостей</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="7">
		Package: <input type="text" name="package" value="github.com/legit/package">
		<button>Проверить пакет</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Typosquatting</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="8">
		Package: <input type="text" name="package" value="golang.org/x/crypto">
		<button>Установить</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Компрометированный репозиторий</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="9">
		Repo: <input type="text" name="repo" value="github.com/company/repo">
		<button>Клонировать репозиторий</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): Цепочка зависимостей</h2>
	<form method="GET" action="/a03">
		<input type="hidden" name="vuln" value="10">
		<button>Показать дерево зависимостей</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	
	// Уязвимость 1: Использование устаревших библиотек
	if vuln == "1" {
		w.Write([]byte("golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 (устарела!)\ngithub.com/gorilla/mux v1.7.0 (устарела!)\nВерсии не обновлялись 5+ лет"))
		return
	}
	
	// Уязвимость 2: Загрузка зависимостей без проверки
	if vuln == "2" {
		packageName := r.URL.Query().Get("package")
		w.Write([]byte(fmt.Sprintf("Пакет %s установлен без проверки подписи и целостности!", packageName)))
		return
	}
	
	// Уязвимость 3: Использование небезопасных источников
	if vuln == "3" {
		url := r.URL.Query().Get("url")
		w.Write([]byte(fmt.Sprintf("Скрипт загружен с %s без проверки источника!", url)))
		return
	}
	
	// Уязвимость 4: Отсутствие проверки целостности
	if vuln == "4" {
		file := r.URL.Query().Get("file")
		w.Write([]byte(fmt.Sprintf("Файл %s загружен без проверки checksum/SHA256!", file)))
		return
	}
	
	// Уязвимость 5: Выполнение произвольного кода (Command Injection)
	if vuln == "5" {
		cmd := r.URL.Query().Get("cmd")
		// ОПАСНО: выполнение команды без проверки
		out, _ := exec.Command("sh", "-c", cmd).Output()
		w.Write([]byte(fmt.Sprintf("Результат: %s", string(out))))
		return
	}
	
	// Уязвимость 6: Небезопасное обновление
	if vuln == "6" {
		version := r.URL.Query().Get("version")
		w.Write([]byte(fmt.Sprintf("Обновление до версии %s выполнено без проверки подписи разработчика!", version)))
		return
	}
	
	// Уязвимость 7: Подмена зависимостей
	if vuln == "7" {
		packageName := r.URL.Query().Get("package")
		w.Write([]byte(fmt.Sprintf("Пакет %s может быть подменен через DNS или репозиторий!", packageName)))
		return
	}
	
	// Уязвимость 8: Typosquatting
	if vuln == "8" {
		packageName := r.URL.Query().Get("package")
		// Принимаем похожие имена пакетов
		if packageName == "golang.org/x/crypto" || packageName == "golang.org/x/crypro" {
			w.Write([]byte(fmt.Sprintf("Пакет %s установлен (возможна опечатка в имени!)", packageName)))
		}
		return
	}
	
	// Уязвимость 9: Компрометированный репозиторий
	if vuln == "9" {
		repo := r.URL.Query().Get("repo")
		w.Write([]byte(fmt.Sprintf("Репозиторий %s клонирован. Если репозиторий скомпрометирован, код может быть вредоносным!", repo)))
		return
	}
	
	// Уязвимость 10: Цепочка зависимостей
	if vuln == "10" {
		w.Write([]byte("Дерево зависимостей:\napp -> libA v1.0 -> libB v2.0 -> libC v1.5 (уязвима!)\napp -> libD v3.0 -> libE v1.0 (устарела!)\nНет проверки транзитивных зависимостей"))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

