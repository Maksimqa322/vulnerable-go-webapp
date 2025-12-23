package endpoints

import (
	"fmt"
	"net/http"
	"os/exec"
)

// A05:2025 - Injection
// 10 уязвимостей разной сложности

// Простая "база данных" в памяти
var fakeDB = map[string]string{
	"1": "User1",
	"2": "User2",
	"3": "Admin",
}

func a05Injection(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A05: Injection</h1>
	<h2>Уязвимость 1 (Легкая): SQL Injection</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="1">
		User ID: <input type="text" name="id" value="1 OR 1=1">
		<button>Найти пользователя</button>
	</form>
	
	<h2>Уязвимость 2 (Легкая): Command Injection</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="2">
		Command: <input type="text" name="cmd" value="ls">
		<button>Выполнить</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): XSS (Cross-Site Scripting)</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="3">
		Name: <input type="text" name="name" value="<script>alert('XSS')</script>">
		<button>Отправить</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): LDAP Injection</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="4">
		Username: <input type="text" name="user" value="admin)(&">
		<button>Поиск LDAP</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): NoSQL Injection</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="5">
		Query: <input type="text" name="query" value="{$ne: null}">
		<button>Поиск NoSQL</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Template Injection</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="6">
		Template: <input type="text" name="template" value="{{.Name}}">
		<button>Рендерить шаблон</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): XXE (XML External Entity)</h2>
	<form method="POST" action="/a05">
		<input type="hidden" name="vuln" value="7">
		XML: <textarea name="xml">&lt;?xml version="1.0"?&gt;&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;&lt;foo&gt;&amp;xxe;&lt;/foo&gt;</textarea>
		<button>Отправить XML</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Code Injection</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="8">
		Code: <input type="text" name="code" value="os.Getenv('PATH')">
		<button>Выполнить код</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Path Traversal</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="9">
		File: <input type="text" name="file" value="../../../etc/passwd">
		<button>Прочитать файл</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): SSRF (Server-Side Request Forgery)</h2>
	<form method="GET" action="/a05">
		<input type="hidden" name="vuln" value="10">
		URL: <input type="text" name="url" value="http://localhost:8080/admin">
		<button>Загрузить URL</button>
	</form>
	`
	
	vuln := r.URL.Query().Get("vuln")
	if r.Method == "POST" {
		vuln = r.FormValue("vuln")
	}
	
	// Уязвимость 1: SQL Injection
	if vuln == "1" {
		id := r.URL.Query().Get("id")
		// ОПАСНО: прямое включение в запрос
		query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
		w.Write([]byte(fmt.Sprintf("SQL запрос: %s\nРезультат: Все пользователи (SQL Injection работает!)", query)))
		return
	}
	
	// Уязвимость 2: Command Injection
	if vuln == "2" {
		cmd := r.URL.Query().Get("cmd")
		// ОПАСНО: выполнение команды
		out, _ := exec.Command("sh", "-c", cmd).Output()
		w.Write([]byte(fmt.Sprintf("Результат команды '%s':\n%s", cmd, string(out))))
		return
	}
	
	// Уязвимость 3: XSS
	if vuln == "3" {
		name := r.URL.Query().Get("name")
		// ОПАСНО: вывод без экранирования
		w.Write([]byte(fmt.Sprintf("<h2>Привет, %s!</h2>", name)))
		return
	}
	
	// Уязвимость 4: LDAP Injection
	if vuln == "4" {
		user := r.URL.Query().Get("user")
		// ОПАСНО: прямое включение в LDAP запрос
		filter := fmt.Sprintf("(uid=%s)", user)
		w.Write([]byte(fmt.Sprintf("LDAP фильтр: %s\nРезультат: Все пользователи (LDAP Injection!)", filter)))
		return
	}
	
	// Уязвимость 5: NoSQL Injection
	if vuln == "5" {
		query := r.URL.Query().Get("query")
		// ОПАСНО: прямое включение в NoSQL запрос
		w.Write([]byte(fmt.Sprintf("NoSQL запрос: db.users.find({%s})\nРезультат: Все документы (NoSQL Injection!)", query)))
		return
	}
	
	// Уязвимость 6: Template Injection
	if vuln == "6" {
		template := r.URL.Query().Get("template")
		// ОПАСНО: выполнение шаблона без проверки
		result := fmt.Sprintf("Результат шаблона: %s", template)
		w.Write([]byte(result))
		return
	}
	
	// Уязвимость 7: XXE
	if vuln == "7" && r.Method == "POST" {
		xml := r.FormValue("xml")
		// ОПАСНО: парсинг XML без отключения внешних сущностей
		w.Write([]byte(fmt.Sprintf("XML обработан:\n%s\n(XXE может прочитать файлы системы!)", xml)))
		return
	}
	
	// Уязвимость 8: Code Injection
	if vuln == "8" {
		code := r.URL.Query().Get("code")
		// ОПАСНО: выполнение кода через eval (в Go нет eval, но демонстрация)
		w.Write([]byte(fmt.Sprintf("Код '%s' выполнен (Code Injection!)", code)))
		return
	}
	
	// Уязвимость 9: Path Traversal
	if vuln == "9" {
		file := r.URL.Query().Get("file")
		// ОПАСНО: чтение файла без проверки пути
		w.Write([]byte(fmt.Sprintf("Попытка чтения файла: %s\n(Path Traversal может прочитать любой файл!)", file)))
		return
	}
	
	// Уязвимость 10: SSRF
	if vuln == "10" {
		url := r.URL.Query().Get("url")
		// ОПАСНО: запрос к любому URL
		w.Write([]byte(fmt.Sprintf("Запрос отправлен на: %s\n(SSRF может обращаться к внутренним ресурсам!)", url)))
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

