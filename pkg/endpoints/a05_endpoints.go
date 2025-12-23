package endpoints

import (
	"fmt"
	"net/http"
	"os/exec"
)

// A05:2025 - Injection
// 10 реалистичных эндпоинтов

// Уязвимость 1: SQL Injection в поиске пользователей
func apiV1UsersSearchSQL(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	// УЯЗВИМОСТЬ: SQL запрос формируется напрямую из пользовательского ввода
	sqlQuery := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%' OR email LIKE '%%%s%%'", query, query)
	
	sendJSON(w, map[string]interface{}{
		"status":    "success",
		"query":     query,
		"sql_query": sqlQuery,
		"results": []map[string]string{
			{"id": "1", "name": "John Doe", "email": "john@example.com"},
			{"id": "2", "name": "Jane Smith", "email": "jane@example.com"},
		},
		"warning": "SQL Injection possible! Try: ' OR '1'='1",
	})
}

// Уязвимость 2: Command Injection в ping
func apiV1NetworkPing(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		host := r.FormValue("host")
		
		// УЯЗВИМОСТЬ: Выполняем команду без санитизации
		cmd := exec.Command("ping", "-c", "4", host)
		out, _ := cmd.Output()
		
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"host":    host,
			"output":  string(out),
			"warning": "Command Injection possible! Try: 8.8.8.8; cat /etc/passwd",
		})
		return
	}
	
	html := renderPage("Network Ping", `
		<div class="card">
			<h2>Ping Host</h2>
			<form method="POST">
				<div class="form-group">
					<label>Host</label>
					<input type="text" name="host" value="8.8.8.8" placeholder="IP or domain">
				</div>
				<button type="submit" class="btn">Ping</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 3: XSS в комментариях
func apiV1Comments(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		comment := r.FormValue("comment")
		user := r.FormValue("user")
		
		// УЯЗВИМОСТЬ: Комментарий выводится без экранирования
		html := renderPage("Comments", fmt.Sprintf(`
			<div class="card">
				<h2>Comment Posted</h2>
				<p><strong>%s:</strong> %s</p>
				<p class="response error">XSS possible! Try: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
			</div>
		`, user, comment))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}
	
	html := renderPage("Post Comment", `
		<div class="card">
			<h2>Post Comment</h2>
			<form method="POST">
				<div class="form-group">
					<label>Your Name</label>
					<input type="text" name="user" value="User">
				</div>
				<div class="form-group">
					<label>Comment</label>
					<textarea name="comment">Great post!</textarea>
				</div>
				<button type="submit" class="btn">Post</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 4: LDAP Injection
func apiV1LdapSearch(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// УЯЗВИМОСТЬ: LDAP запрос формируется напрямую
	ldapQuery := fmt.Sprintf("(uid=%s)", username)
	
	sendJSON(w, map[string]interface{}{
		"status":    "success",
		"ldap_query": ldapQuery,
		"results": []map[string]string{
			{"uid": username, "cn": "User Name", "mail": "user@company.com"},
		},
		"warning": "LDAP Injection possible! Try: admin)(&",
	})
}

// Уязвимость 5: NoSQL Injection
func apiV1UsersFind(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	
	// УЯЗВИМОСТЬ: NoSQL запрос выполняется напрямую
	mongoQuery := fmt.Sprintf("db.users.find({%s})", query)
	
	sendJSON(w, map[string]interface{}{
		"status":     "success",
		"mongo_query": mongoQuery,
		"results": []map[string]string{
			{"id": "1", "username": "admin", "role": "admin"},
			{"id": "2", "username": "user", "role": "user"},
		},
		"warning": "NoSQL Injection possible! Try: {\"$ne\": null}",
	})
}

// Уязвимость 6: Template Injection
func apiV1Render(w http.ResponseWriter, r *http.Request) {
	template := r.URL.Query().Get("template")
	
	// УЯЗВИМОСТЬ: Шаблон выполняется без проверки
	result := fmt.Sprintf("Rendered: %s", template)
	
	sendJSON(w, map[string]interface{}{
		"status":   "success",
		"template": template,
		"result":   result,
		"warning": "Template Injection possible!",
	})
}

// Уязвимость 7: XXE в XML парсере
func apiV1XmlParse(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		xml := r.FormValue("xml")
		
		// УЯЗВИМОСТЬ: XML парсится без отключения внешних сущностей
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "XML parsed without disabling external entities",
			"xml":     xml,
			"warning": "XXE possible! Try: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
		})
		return
	}
	
	html := renderPage("Parse XML", `
		<div class="card">
			<h2>Parse XML</h2>
			<form method="POST">
				<div class="form-group">
					<label>XML Content</label>
					<textarea name="xml"><root><data>test</data></root></textarea>
				</div>
				<button type="submit" class="btn">Parse</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 8: Path Traversal в загрузке файлов
func apiV1FilesDownload(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	
	// УЯЗВИМОСТЬ: Нет проверки пути, можно читать любые файлы
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"file":    file,
		"content": fmt.Sprintf("Content of file: %s", file),
		"warning": "Path Traversal possible! Try: ../../../etc/passwd",
	})
}

// Уязвимость 9: SSRF в webhook
func apiV1Webhook(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	
	// УЯЗВИМОСТЬ: Запрос к любому URL без проверки
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Request sent to: %s", url),
		"warning": "SSRF possible! Try: http://localhost:8080/admin or file:///etc/passwd",
	})
}

// Уязвимость 10: Code Injection через eval
func apiV1Execute(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		code := r.FormValue("code")
		
		// УЯЗВИМОСТЬ: Код выполняется напрямую (в реальности через eval)
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"code":    code,
			"result":  "Code executed",
			"warning": "Code Injection possible!",
		})
		return
	}
	
	html := renderPage("Execute Code", `
		<div class="card">
			<h2>Execute Code</h2>
			<form method="POST">
				<div class="form-group">
					<label>Code</label>
					<textarea name="code">console.log('Hello')</textarea>
				</div>
				<button type="submit" class="btn">Execute</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

