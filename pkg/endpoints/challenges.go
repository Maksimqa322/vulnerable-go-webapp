package endpoints

import (
	"fmt"
	"net/http"
	"strings"
)

// Структура для хранения выполненных заданий (в реальности нужно использовать БД или сессии)
var completedChallenges = make(map[string]bool)

// Страница с заданием для уязвимости
func challengePage(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID уязвимости из пути /challenge/{category}/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/challenge/"), "/")
	if len(pathParts) < 2 {
		http.Error(w, "Неверный путь", 404)
		return
	}
	
	category := pathParts[0]
	vulnID := pathParts[1]
	challengeKey := category + "_" + vulnID
	
	// Получаем задание и проверяем решение
	challenge := getChallenge(category, vulnID, r)
	
	// Проверяем, выполнено ли задание
	isCompleted := completedChallenges[challengeKey]
	
	// Определяем badge цвет
	badgeClass := "badge-info"
	if challenge.Difficulty == "Средний" {
		badgeClass = "badge-warning"
	} else if challenge.Difficulty == "Сложный" {
		badgeClass = "badge-danger"
	}
	
	// Определяем класс ответа и сообщение
	responseClass := ""
	responseMsg := challenge.Hint
	if isCompleted {
		responseClass = "success"
		responseMsg = `<span class="checkmark">✅</span> <strong>Задание выполнено!</strong> Вы успешно эксплуатировали уязвимость.`
	}
	
	html := renderPage("Задание: "+challenge.Title, fmt.Sprintf(`
		<div class="card">
			<h2>%s</h2>
			<p><strong>Категория:</strong> %s</p>
			<p><strong>Уровень сложности:</strong> <span class="badge %s">%s</span></p>
			<p>%s</p>
		</div>
		
		<div class="card">
			<h2>Задание</h2>
			<p>%s</p>
			<div class="response %s">
				%s
			</div>
		</div>
		
		<div class="card">
			<h2>Подсказки</h2>
			<p>%s</p>
		</div>
		
		%s
		
		<div class="card">
			<h2>📚 Подробное объяснение</h2>
			%s
		</div>
	`, 
		challenge.Title,
		challenge.Category,
		badgeClass,
		challenge.Difficulty,
		challenge.Description,
		challenge.Task,
		responseClass,
		responseMsg,
		challenge.Hint,
		challenge.FormHTML,
		challenge.Explanation,
	))
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Структура задания
type Challenge struct {
	Title       string
	Category    string
	Difficulty  string
	Description string
	Task        string
	Hint        string
	FormHTML    string
	Explanation string // Подробное объяснение уязвимости с примерами кода
	CheckFunc   func(*http.Request) bool
}

// Получить задание по категории и ID
func getChallenge(category, vulnID string, r *http.Request) Challenge {
	challengeKey := category + "_" + vulnID
	
	// Проверяем решение, если был отправлен запрос
	if r.Method == "POST" || r.URL.Query().Get("check") != "" {
		challenge := getChallengeData(category, vulnID)
		if challenge.CheckFunc != nil && challenge.CheckFunc(r) {
			completedChallenges[challengeKey] = true
		}
	}
	
	return getChallengeData(category, vulnID)
}

// Получить данные задания
func getChallengeData(category, vulnID string) Challenge {
	challenges := getAllChallenges()
	key := category + "_" + vulnID
	if challenge, ok := challenges[key]; ok {
		return challenge
	}
	
	// Дефолтное задание
	return Challenge{
		Title:       "Задание не найдено",
		Category:    category,
		Difficulty:  "Неизвестно",
		Description: "Уязвимость не найдена",
		Task:        "Попробуйте другую уязвимость",
		Hint:        "",
		FormHTML:    "",
	}
}

// Все задания для всех уязвимостей
func getAllChallenges() map[string]Challenge {
	challenges := make(map[string]Challenge)
	
	// A01: Broken Access Control
	challenges["a01_1"] = Challenge{
		Title:       "IDOR - Получите данные другого пользователя",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Легкий",
		Description: "В этом эндпоинте есть уязвимость IDOR. Вы можете получить данные любого пользователя, зная его ID.",
		Task:        "Получите данные пользователя с ID=2 (не вашего). Подсказка: что если изменить число в URL?",
		Hint:        "💡 Попробуйте изменить ID в URL. Например, если ваш ID=1, попробуйте ID=2 или ID=3.",
		Explanation: `
			<h3>Проблема</h3>
			<p>API эндпоинт <code>/api/v1/users/{id}</code> не проверяет, имеет ли текущий пользователь право доступа к запрашиваемому ID. Любой может изменить ID в URL и получить данные других пользователей.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersID(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
    userID := path
    
    // УЯЗВИМОСТЬ: Нет проверки, что пользователь запрашивает только свой профиль
    users := map[string]map[string]string{
        "1": {"id": "1", "email": "john.doe@company.com", "balance": "50000"},
        "2": {"id": "2", "email": "jane.smith@company.com", "balance": "75000"},
    }
    
    if user, ok := users[userID]; ok {
        sendJSON(w, map[string]interface{}{"data": user})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет, совпадает ли ID текущего пользователя (из сессии или токена) с запрашиваемым ID. Злоумышленник может просто изменить URL с <code>/api/v1/users/1</code> на <code>/api/v1/users/2</code> и получить чужие данные, включая email, баланс и другую чувствительную информацию.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersID(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
    requestedUserID := path
    
    // Получаем ID текущего пользователя из сессии/токена
    currentUserID := getCurrentUserID(r)
    
    // ПРОВЕРКА: Пользователь может запрашивать только свой профиль
    if currentUserID != requestedUserID {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Откройте эндпоинт: <a href="/api/v1/users/1" target="_blank" class="api-endpoint">/api/v1/users/1</a></p>
				<p>Попробуйте изменить ID в URL и получить данные другого пользователя.</p>
				<form method="GET" action="/challenge/a01/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой ID вы использовали для получения чужих данных?</label>
						<input type="text" name="user_id" placeholder="например: 2" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			userID := r.URL.Query().Get("user_id")
			return userID == "2" || userID == "3"
		},
	}
	
	challenges["a01_2"] = Challenge{
		Title:       "Обход авторизации через параметр",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Легкий",
		Description: "Админские права проверяются через GET-параметр. Это очень небезопасно!",
		Task:        "Получите доступ к списку всех пользователей, используя параметр запроса.",
		Hint:        "💡 Что если добавить параметр is_admin в URL? Попробуйте разные значения: true, 1, True...",
		Explanation: `
			<h3>Проблема</h3>
			<p>Админские права проверяются через GET-параметр <code>is_admin</code>, который можно легко подделать в URL.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AdminUsers(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Проверка админ прав через GET параметр
    isAdmin := r.URL.Query().Get("is_admin")
    
    if isAdmin == "true" || isAdmin == "1" {
        // Показать всех пользователей
        sendJSON(w, map[string]interface{}{"data": users})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Параметры запроса контролируются клиентом и могут быть легко изменены. Злоумышленник может просто добавить <code>?is_admin=true</code> к любому URL и получить админский доступ без реальной авторизации.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AdminUsers(w http.ResponseWriter, r *http.Request) {
    // Получаем пользователя из сессии/токена
    user := getCurrentUser(r)
    
    // ПРОВЕРКА: Проверяем роль из серверной сессии, а не из параметров
    if user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/admin/users" target="_blank" class="api-endpoint">/api/v1/admin/users</a></p>
				<p>Попробуйте добавить параметр для получения доступа.</p>
				<form method="GET" action="/challenge/a01/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какое значение параметра вы использовали?</label>
						<input type="text" name="param_value" placeholder="например: true" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			param := r.URL.Query().Get("param_value")
			return param == "true" || param == "1"
		},
	}
	
	challenges["a01_3"] = Challenge{
		Title:       "Небезопасный редирект",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Средний",
		Description: "После логина приложение перенаправляет на URL из параметра без проверки.",
		Task:        "Создайте ссылку, которая перенаправит на внешний сайт после логина.",
		Hint:        "💡 Попробуйте использовать параметр redirect в форме логина. Что если указать внешний URL?",
		Explanation: `
			<h3>Проблема</h3>
			<p>Приложение перенаправляет пользователя на любой URL без проверки, что позволяет создать фишинговую ссылку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthLoginRedirect(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        redirect := r.FormValue("redirect")
        // УЯЗВИМОСТЬ: Редирект на любой URL без проверки
        if redirect != "" {
            http.Redirect(w, r, redirect, 302)
            return
        }
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>URL для редиректа берется напрямую из пользовательского ввода без валидации. Злоумышленник может создать ссылку, которая перенаправит на фишинговый сайт после того, как пользователь войдет в систему.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthLoginRedirect(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        redirect := r.FormValue("redirect")
        
        // ПРОВЕРКА: Разрешаем только относительные пути или наш домен
        if redirect != "" {
            // Разрешаем только относительные пути
            if strings.HasPrefix(redirect, "/") && !strings.Contains(redirect, "://") {
                http.Redirect(w, r, redirect, 302)
                return
            }
            // Или проверяем, что URL принадлежит нашему домену
            if strings.HasPrefix(redirect, "https://ourdomain.com") {
                http.Redirect(w, r, redirect, 302)
                return
            }
        }
        // По умолчанию редирект на главную
        http.Redirect(w, r, "/", 302)
    }
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/login" target="_blank" class="api-endpoint">/api/v1/auth/login</a></p>
				<p>Попробуйте указать внешний URL в параметре redirect.</p>
				<form method="GET" action="/challenge/a01/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой внешний URL вы использовали в redirect?</label>
						<input type="text" name="redirect_url" placeholder="например: http://evil.com" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			url := r.URL.Query().Get("redirect_url")
			return strings.Contains(url, "://") && !strings.HasPrefix(url, "/")
		},
	}
	
	// A02: Security Misconfiguration
	challenges["a02_1"] = Challenge{
		Title:       "Открытый .env файл",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Легкий",
		Description: "Файл с секретными данными доступен через веб-сервер.",
		Task:        "Получите доступ к файлу .env и найдите секретный ключ базы данных.",
		Hint:        "💡 Попробуйте открыть /.env напрямую в браузере. Файлы, начинающиеся с точки, часто доступны по ошибке.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Файл с секретными данными (.env) доступен через веб-сервер, что позволяет злоумышленнику получить все секретные ключи, пароли и токены.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ConfigEnv(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: .env файл доступен через веб-сервер
    w.Write([]byte("DATABASE_URL=postgresql://admin:password@db:5432\nAWS_SECRET_KEY=secret123"))
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Веб-сервер настроен так, что отдает файлы из корневой директории, включая конфигурационные файлы. Это часто происходит из-за неправильной настройки nginx/apache или когда файлы случайно попадают в публичную директорию.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>// НЕ создавайте эндпоинт для .env файла
// Настройте веб-сервер так, чтобы он блокировал доступ к файлам, начинающимся с точки
// В nginx:
// location ~ /\. {
//     deny all;
// }

// Или храните секреты в переменных окружения, а не в файлах
// Используйте секретные менеджеры (AWS Secrets Manager, HashiCorp Vault)
</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Попробуйте открыть: <a href="/.env" target="_blank" class="api-endpoint">/.env</a></p>
				<form method="GET" action="/challenge/a02/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой ключ базы данных вы нашли? (DATABASE_URL)</label>
						<input type="text" name="db_key" placeholder="например: postgresql://..." required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			dbKey := r.URL.Query().Get("db_key")
			return strings.Contains(dbKey, "postgresql") || strings.Contains(dbKey, "DATABASE_URL")
		},
	}
	
	// A05: Injection
	challenges["a05_1"] = Challenge{
		Title:       "SQL Injection",
		Category:    "A05: Injection",
		Difficulty:  "Средний",
		Description: "Пользовательский ввод напрямую вставляется в SQL запрос без проверки.",
		Task:        "Используйте SQL Injection, чтобы получить всех пользователей вместо одного.",
		Hint:        "💡 Попробуйте добавить SQL код в параметр поиска. Что если использовать ' OR '1'='1 ?",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пользовательский ввод напрямую вставляется в SQL запрос без проверки, что позволяет выполнить произвольный SQL код.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersSearchSQL(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // УЯЗВИМОСТЬ: SQL запрос формируется напрямую из пользовательского ввода
    sqlQuery := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", query)
    
    db.Query(sqlQuery)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не использует параметризованные запросы (prepared statements) и напрямую вставляет пользовательский ввод в SQL запрос. Это позволяет злоумышленнику выполнить произвольный SQL код, например: <code>' OR '1'='1</code> для получения всех записей.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersSearchSQL(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // ПРОВЕРКА: Используем параметризованные запросы
    sqlQuery := "SELECT * FROM users WHERE name LIKE ? OR email LIKE ?"
    rows, err := db.Query(sqlQuery, "%"+query+"%", "%"+query+"%")
    
    // Параметры автоматически экранируются и не могут быть интерпретированы как SQL
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/search?q=test" target="_blank" class="api-endpoint">/api/v1/users/search?q=test</a></p>
				<p>Попробуйте изменить параметр q, чтобы выполнить SQL Injection.</p>
				<form method="GET" action="/challenge/a05/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой SQL код вы использовали в параметре q?</label>
						<input type="text" name="sql_payload" placeholder="например: ' OR '1'='1" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			payload := r.URL.Query().Get("sql_payload")
			return strings.Contains(payload, "OR") && strings.Contains(payload, "1") && strings.Contains(payload, "'")
		},
	}
	
	challenges["a05_2"] = Challenge{
		Title:       "Command Injection",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "Пользовательский ввод передается в системную команду без санитизации.",
		Task:        "Выполните команду ls через параметр host в ping.",
		Hint:        "💡 В shell точка с запятой (;) разделяет команды. Что если добавить ; ls после IP адреса?",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пользовательский ввод передается в системную команду без санитизации, что позволяет выполнить произвольные команды.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1NetworkPing(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue("host")
    
    // УЯЗВИМОСТЬ: Выполняем команду без санитизации
    cmd := exec.Command("ping", "-c", "4", host)
    out, _ := cmd.Output()
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не валидирует и не санитизирует пользовательский ввод перед передачей в системную команду. Это позволяет злоумышленнику выполнить произвольные команды, используя разделители команд (; или &&).</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1NetworkPing(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue("host")
    
    // ПРОВЕРКА: Валидируем и санитизируем ввод
    if !isValidHostname(host) && !isValidIP(host) {
        http.Error(w, "Invalid host", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Используем whitelist разрешенных символов
    // ПРОВЕРКА: Используем exec.Command с отдельными аргументами (не shell)
    cmd := exec.Command("ping", "-c", "4", host)
    out, _ := cmd.Output()
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/network/ping" target="_blank" class="api-endpoint">/api/v1/network/ping</a></p>
				<p>Попробуйте выполнить команду ls через параметр host.</p>
				<form method="GET" action="/challenge/a05/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какую команду вы выполнили? (напишите только команду, например: ls)</label>
						<input type="text" name="command" placeholder="например: ls" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			cmd := r.URL.Query().Get("command")
			return cmd == "ls" || cmd == "cat" || cmd == "pwd"
		},
	}
	
	challenges["a05_3"] = Challenge{
		Title:       "XSS (Cross-Site Scripting)",
		Category:    "A05: Injection",
		Difficulty:  "Легкий",
		Description: "Пользовательский ввод выводится без экранирования, что позволяет выполнить JavaScript.",
		Task:        "Выполните JavaScript alert('XSS') через комментарий.",
		Hint:        "💡 Попробуйте вставить тег &lt;script&gt; с alert в поле комментария.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пользовательский ввод выводится без экранирования, что позволяет выполнить произвольный JavaScript код в браузере жертвы.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Comments(w http.ResponseWriter, r *http.Request) {
    comment := r.FormValue("comment")
    
    // УЯЗВИМОСТЬ: Выводим комментарий без экранирования
    html := fmt.Sprintf("&lt;div&gt;%s&lt;/div&gt;", comment)
    w.Write([]byte(html))
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не экранирует HTML/JavaScript специальные символы перед выводом. Это позволяет злоумышленнику вставить JavaScript код, который будет выполнен в браузере жертвы.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Comments(w http.ResponseWriter, r *http.Request) {
    comment := r.FormValue("comment")
    
    // ПРОВЕРКА: Экранируем HTML специальные символы
    escapedComment := html.EscapeString(comment)
    html := fmt.Sprintf("&lt;div&gt;%s&lt;/div&gt;", escapedComment)
    w.Write([]byte(html))
    
    // Или используем шаблонизаторы с автоматическим экранированием
    // template.HTMLEscapeString(comment)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/comments" target="_blank" class="api-endpoint">/api/v1/comments</a></p>
				<p>Попробуйте отправить комментарий с JavaScript кодом.</p>
				<form method="GET" action="/challenge/a05/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой тег вы использовали? (напишите только тег, например: script)</label>
						<input type="text" name="tag" placeholder="например: script" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			tag := strings.ToLower(r.URL.Query().Get("tag"))
			return tag == "script" || strings.Contains(tag, "script")
		},
	}
	
	// A04: Cryptographic Failures
	challenges["a04_1"] = Challenge{
		Title:       "Пароли в открытом виде",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Легкий",
		Description: "Пароли хранятся в базе данных без хеширования.",
		Task:        "Получите пароль пользователя с ID=1 через API.",
		Hint:        "💡 Попробуйте запросить /api/v1/users/password с параметром user_id.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пароли хранятся в базе данных в открытом виде без хеширования, что позволяет получить их напрямую при утечке данных.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersPasswordPlain(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    // УЯЗВИМОСТЬ: Возвращаем пароли в открытом виде
    passwords := map[string]string{
        "1": "password123",
        "2": "admin123",
    }
    
    if pass, ok := passwords[userID]; ok {
        sendJSON(w, map[string]interface{}{"password": pass})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Пароли хранятся в базе данных без хеширования. При утечке данных или компрометации базы данных злоумышленник может получить все пароли в открытом виде.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersPasswordPlain(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    // ПРОВЕРКА: НИКОГДА не возвращаем пароли
    // Пароли должны храниться только в виде хешей (bcrypt, argon2)
    
    // При сохранении пароля:
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    // Сохраняем только hashedPassword в БД
    
    // При проверке пароля:
    err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(inputPassword))
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/password?user_id=1" target="_blank" class="api-endpoint">/api/v1/users/password?user_id=1</a></p>
				<form method="GET" action="/challenge/a04/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пароль вы получили?</label>
						<input type="text" name="password" placeholder="например: password123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pass := r.URL.Query().Get("password")
			return pass == "password123"
		},
	}
	
	challenges["a04_2"] = Challenge{
		Title:       "Использование MD5",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Средний",
		Description: "MD5 - устаревший алгоритм хеширования, который легко взломать.",
		Task:        "Получите MD5 хеш пароля 'test123' и найдите его в базе rainbow tables.",
		Hint:        "💡 Используйте эндпоинт /api/v1/auth/hash для получения хеша. MD5 хеш 'test123' начинается с 'cc0'.",
		Explanation: `
			<h3>Проблема</h3>
			<p>MD5 - устаревший алгоритм хеширования, который легко взломать через rainbow tables и brute force атаки.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthHash(w http.ResponseWriter, r *http.Request) {
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Используем MD5 для хеширования (легко взломать)
    hash := md5.Sum([]byte(password))
    sendJSON(w, map[string]interface{}{"hash": fmt.Sprintf("%x", hash)})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>MD5 был разработан в 1991 году и сейчас считается небезопасным. Существуют огромные базы данных (rainbow tables) с предвычисленными хешами, что позволяет быстро найти исходный пароль.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthHash(w http.ResponseWriter, r *http.Request) {
    password := r.FormValue("password")
    
    // ПРОВЕРКА: Используем современные алгоритмы (bcrypt, argon2, scrypt)
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    
    // bcrypt автоматически добавляет salt и использует достаточное количество раундов
    sendJSON(w, map[string]interface{}{"hash": string(hashedPassword)})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/hash" target="_blank" class="api-endpoint">/api/v1/auth/hash</a></p>
				<form method="GET" action="/challenge/a04/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Первые 3 символа MD5 хеша 'test123'?</label>
						<input type="text" name="hash_start" placeholder="например: cc0" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			hashStart := strings.ToLower(r.URL.Query().Get("hash_start"))
			// MD5 от "test123" = cc03e747a6afbbcbf8be7668acfebee5
			return hashStart == "cc0"
		},
	}
	
	// A01: Продолжение
	challenges["a01_4"] = Challenge{
		Title:       "Слабая проверка JWT токена",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Средний",
		Description: "JWT токен проверяется очень слабо - достаточно, чтобы в нем было слово 'admin'.",
		Task:        "Получите админский доступ, используя поддельный JWT токен.",
		Hint:        "💡 Попробуйте использовать токен, содержащий слово 'admin'. Эндпоинт: /api/v1/auth/verify",
		Explanation: `
			<h3>Проблема</h3>
			<p>JWT токен проверяется очень слабо - достаточно, чтобы в токене было слово "admin", без проверки подписи или структуры токена.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthVerifyJWT(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    
    // УЯЗВИМОСТЬ: Принимаем любой токен, который содержит "admin"
    if strings.Contains(token, "admin") {
        sendJSON(w, map[string]interface{}{
            "status": "success",
            "user":   "admin",
            "role":   "administrator",
        })
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет подпись JWT токена, его структуру или срок действия. Достаточно просто передать строку, содержащую слово "admin", чтобы получить админский доступ.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthVerifyJWT(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    
    // ПРОВЕРКА: Проверяем подпись и структуру JWT
    claims, err := verifyJWTToken(token)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    
    // Проверяем роль из токена
    if claims.Role == "admin" {
        sendJSON(w, map[string]interface{}{
            "status": "success",
            "user":   claims.UserID,
            "role":   "administrator",
        })
    }
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/verify?token=admin" target="_blank" class="api-endpoint">/api/v1/auth/verify?token=admin</a></p>
				<form method="GET" action="/challenge/a01/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какое слово должно быть в токене?</label>
						<input type="text" name="token_word" placeholder="например: admin" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			word := strings.ToLower(r.URL.Query().Get("token_word"))
			return word == "admin"
		},
	}
	
	challenges["a01_5"] = Challenge{
		Title:       "Прямой доступ к файлам",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Легкий",
		Description: "Файлы доступны напрямую через API без проверки прав доступа.",
		Task:        "Получите содержимое файла config.json через API.",
		Hint:        "💡 Попробуйте запросить /api/v1/files с параметром file=config.json",
		Explanation: `
			<h3>Проблема</h3>
			<p>Файлы доступны напрямую через API без проверки прав доступа. Можно читать любые файлы, включая конфигурационные файлы с секретами.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Files(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    
    // УЯЗВИМОСТЬ: Нет проверки пути, можно читать любые файлы
    if file == "config.json" {
        w.Write([]byte("{\"database\": \"postgresql://admin:password@db:5432/prod\"}"))
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет права доступа пользователя и не валидирует путь к файлу. Злоумышленник может запросить любой файл, включая конфигурационные файлы с паролями и API ключами.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Files(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    
    // ПРОВЕРКА: Проверяем права доступа
    user := getCurrentUser(r)
    if !user.HasPermission("read_files") {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Валидируем путь к файлу (запрещаем path traversal)
    if strings.Contains(file, "..") || strings.Contains(file, "/") {
        http.Error(w, "Invalid file path", http.StatusBadRequest)
        return
    }
    
    // Разрешаем только файлы из безопасной директории
    safePath := filepath.Join("/safe/directory", file)
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/files?file=config.json" target="_blank" class="api-endpoint">/api/v1/files?file=config.json</a></p>
				<form method="GET" action="/challenge/a01/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой файл вы получили?</label>
						<input type="text" name="file_name" placeholder="например: config.json" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			fileName := r.URL.Query().Get("file_name")
			return fileName == "config.json"
		},
	}
	
	// A02: Продолжение
	challenges["a02_2"] = Challenge{
		Title:       "Отладочная информация в production",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Средний",
		Description: "При ошибках показывается полный stack trace с чувствительными данными.",
		Task:        "Получите информацию о базе данных из сообщения об ошибке.",
		Hint:        "💡 Попробуйте вызвать ошибку в эндпоинте /api/v1/debug/users/search, оставив параметр q пустым.",
		Explanation: `
			<h3>Проблема</h3>
			<p>При ошибках показывается полный stack trace с чувствительными данными (SQL запросы, пути к файлам, версии технологий).</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersSearchDebug(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // УЯЗВИМОСТЬ: Показываем полный stack trace и SQL запрос
    if query == "" {
        w.Write([]byte("Error: Empty query parameter\nStack Trace: UserService.java:142\nSQL Query: SELECT * FROM users\nDatabase: postgresql://prod-db.internal:5432"))
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>В production-окружении включен режим отладки или не настроена правильная обработка ошибок. Это раскрывает внутреннюю структуру приложения, пути к файлам, версии технологий и SQL запросы.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersSearchDebug(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    if query == "" {
        // В production показываем только общее сообщение
        http.Error(w, "Query parameter is required", http.StatusBadRequest)
        
        // Детали логируем в безопасное место (не показываем пользователю)
        log.Printf("[ERROR] Empty query parameter from IP: %s", r.RemoteAddr)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/debug/users/search?q=" target="_blank" class="api-endpoint">/api/v1/debug/users/search?q=</a></p>
				<form method="GET" action="/challenge/a02/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая информация о базе данных была раскрыта? (напишите: database или postgresql)</label>
						<input type="text" name="db_info" placeholder="например: database" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			info := strings.ToLower(r.URL.Query().Get("db_info"))
			return strings.Contains(info, "database") || strings.Contains(info, "postgresql")
		},
	}
	
	// A06: Insecure Design
	challenges["a06_1"] = Challenge{
		Title:       "Отсутствие rate limiting",
		Category:    "A06: Insecure Design",
		Difficulty:  "Легкий",
		Description: "Нет ограничения на количество запросов от одного IP.",
		Task:        "Отправьте 10 запросов на эндпоинт логина за 1 секунду (симулируйте брутфорс).",
		Hint:        "💡 Попробуйте быстро отправить несколько запросов на /api/v1/a06/auth/login. Используйте curl или скрипт.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет ограничения на количество запросов от одного IP, что позволяет выполнить брутфорс атаку для подбора паролей.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthLoginNoRateLimit(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет ограничения на количество попыток входа
    if checkPassword(email, password) {
        sendJSON(w, map[string]interface{}{"status": "success"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не ограничивает количество запросов от одного IP адреса. Это позволяет злоумышленнику отправить тысячи запросов для подбора паролей (брутфорс атака).</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthLoginNoRateLimit(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // ПРОВЕРКА: Ограничиваем количество попыток входа
    ip := getClientIP(r)
    if !rateLimiter.Allow(ip) {
        http.Error(w, "Too many requests", http.StatusTooManyRequests)
        return
    }
    
    // ПРОВЕРКА: Блокируем аккаунт после нескольких неудачных попыток
    if failedAttempts(email) > 5 {
        http.Error(w, "Account locked", http.StatusForbidden)
        return
    }
    
    if checkPassword(email, password) {
        sendJSON(w, map[string]interface{}{"status": "success"})
    }
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/a06/auth/login" target="_blank" class="api-endpoint">/api/v1/a06/auth/login</a></p>
				<p>Попробуйте отправить несколько запросов быстро.</p>
				<form method="GET" action="/challenge/a06/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Сколько запросов вы отправили? (минимум 5)</label>
						<input type="number" name="request_count" placeholder="например: 10" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			count := r.URL.Query().Get("request_count")
			return count >= "5"
		},
	}
	
	challenges["a06_2"] = Challenge{
		Title:       "Слабая валидация email",
		Category:    "A06: Insecure Design",
		Difficulty:  "Легкий",
		Description: "Нет проверки формата email, можно зарегистрироваться с невалидным email.",
		Task:        "Зарегистрируйтесь с невалидным email (например, not-an-email) без проверки формата.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/users/register с email=not-an-email",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет проверки формата email, можно зарегистрироваться с невалидным email, что может привести к проблемам с восстановлением пароля и уведомлениями.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersRegister(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    // УЯЗВИМОСТЬ: Нет проверки формата email
    createUser(email)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не валидирует формат email перед регистрацией. Это позволяет зарегистрироваться с невалидным email, что может привести к проблемам с восстановлением пароля, уведомлениями и безопасностью.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersRegister(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    // ПРОВЕРКА: Валидируем формат email
    if !isValidEmail(email) {
        http.Error(w, "Invalid email format", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что email не зарегистрирован
    if userExists(email) {
        http.Error(w, "Email already registered", http.StatusConflict)
        return
    }
    
    // ПРОВЕРКА: Отправляем подтверждение на email
    sendVerificationEmail(email)
    
    createUser(email)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/register" target="_blank" class="api-endpoint">/api/v1/users/register</a></p>
				<form method="GET" action="/challenge/a06/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой невалидный email вы использовали? (например: not-an-email)</label>
						<input type="text" name="email" placeholder="например: not-an-email" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			email := r.URL.Query().Get("email")
			return !strings.Contains(email, "@") || email == "not-an-email"
		},
	}
	
	// A07: Authentication Failures
	challenges["a07_1"] = Challenge{
		Title:       "Слабые пароли по умолчанию",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Легкий",
		Description: "Система использует стандартные пароли, которые не были изменены.",
		Task:        "Войдите в систему используя стандартные учетные данные admin@company.com.",
		Hint:        "💡 Попробуйте стандартные пароли: admin, admin123, password, 12345...",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/default/login" target="_blank" class="api-endpoint">/api/v1/auth/default/login</a></p>
				<form method="GET" action="/challenge/a07/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пароль вы использовали?</label>
						<input type="text" name="password" placeholder="например: admin123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pass := r.URL.Query().Get("password")
			return pass == "admin123"
		},
	}
	
	challenges["a07_2"] = Challenge{
		Title:       "Отсутствие блокировки после неудачных попыток",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Средний",
		Description: "Можно бесконечно пытаться угадать пароль без блокировки аккаунта.",
		Task:        "Попробуйте войти 5 раз с неправильным паролем (симулируйте брутфорс).",
		Hint:        "💡 Отправьте несколько POST запросов на /api/v1/auth/bruteforce с неправильным паролем.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Можно бесконечно пытаться угадать пароль без блокировки аккаунта, что позволяет выполнить брутфорс атаку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthBruteforce(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет блокировки после неудачных попыток
    if checkPassword(email, password) {
        sendJSON(w, map[string]interface{}{"status": "success"})
    } else {
        sendJSON(w, map[string]interface{}{"status": "error"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не отслеживает количество неудачных попыток входа и не блокирует аккаунт после нескольких неудачных попыток. Это позволяет злоумышленнику выполнить брутфорс атаку для подбора пароля.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthBruteforce(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // ПРОВЕРКА: Проверяем количество неудачных попыток
    failedAttempts := getFailedAttempts(email)
    if failedAttempts >= 5 {
        http.Error(w, "Account locked due to too many failed attempts", http.StatusForbidden)
        return
    }
    
    if checkPassword(email, password) {
        resetFailedAttempts(email)
        sendJSON(w, map[string]interface{}{"status": "success"})
    } else {
        incrementFailedAttempts(email)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
    }
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/bruteforce" target="_blank" class="api-endpoint">/api/v1/auth/bruteforce</a></p>
				<form method="GET" action="/challenge/a07/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Сколько неудачных попыток вы сделали? (минимум 5)</label>
						<input type="number" name="attempts" placeholder="например: 5" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			attempts := r.URL.Query().Get("attempts")
			return attempts >= "5"
		},
	}
	
	// A09: Logging Failures
	challenges["a09_1"] = Challenge{
		Title:       "Чувствительные данные в логах",
		Category:    "A09: Logging Failures",
		Difficulty:  "Легкий",
		Description: "Пароли логируются в открытом виде при попытке входа.",
		Task:        "Попробуйте войти и найдите свой пароль в логах сервера.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/a09/auth/login. Пароль будет залогирован в консоль сервера.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пароли логируются в открытом виде при попытке входа, что позволяет злоумышленнику получить их при доступе к логам.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthLoginLogSensitive(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Пароль логируется в открытом виде
    fmt.Printf("[LOG] Login attempt - email: %s, password: %s\\n", email, password)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код логирует пароль в открытом виде. При доступе к логам (например, через утечку или компрометацию сервера) злоумышленник может получить все пароли пользователей.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthLoginLogSensitive(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // ПРОВЕРКА: НИКОГДА не логируем пароли
    // Логируем только email и результат попытки входа
    fmt.Printf("[LOG] Login attempt - email: %s, result: %s\\n", email, "success/error")
    
    // ПРОВЕРКА: Если нужно логировать попытки входа, используем только email и IP
    fmt.Printf("[LOG] Login attempt - email: %s, IP: %s, timestamp: %s\\n", 
        email, r.RemoteAddr, time.Now())
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/a09/auth/login" target="_blank" class="api-endpoint">/api/v1/a09/auth/login</a></p>
				<p>Попробуйте войти с любым паролем. Пароль будет залогирован на сервере.</p>
				<form method="GET" action="/challenge/a09/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пароль вы использовали? (он должен быть в логах)</label>
						<input type="text" name="logged_password" placeholder="например: secret123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pass := r.URL.Query().Get("logged_password")
			return len(pass) > 0
		},
	}
	
	// A10: Exception Handling
	challenges["a10_1"] = Challenge{
		Title:       "Раскрытие информации в ошибках",
		Category:    "A10: Exception Handling",
		Difficulty:  "Средний",
		Description: "При ошибке показывается полный stack trace с внутренними деталями системы.",
		Task:        "Вызовите ошибку и получите информацию о базе данных из сообщения об ошибке.",
		Hint:        "💡 Попробуйте запросить /api/v1/users/get без параметра user_id.",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/get" target="_blank" class="api-endpoint">/api/v1/users/get</a></p>
				<p>Попробуйте вызвать ошибку, не указав обязательный параметр.</p>
				<form method="GET" action="/challenge/a10/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая информация о базе данных была раскрыта? (напишите: database или postgresql)</label>
						<input type="text" name="exposed_info" placeholder="например: database" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			info := strings.ToLower(r.URL.Query().Get("exposed_info"))
			return strings.Contains(info, "database") || strings.Contains(info, "postgresql") || strings.Contains(info, "stack")
		},
	}
	
	// A01: Остальные задания (6-10)
	challenges["a01_6"] = Challenge{
		Title:       "Обход через заголовки",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Средний",
		Description: "Админские права проверяются через HTTP заголовки, которые можно подделать.",
		Task:        "Получите доступ к конфигурации админа, используя заголовок X-Admin.",
		Hint:        "💡 Попробуйте отправить запрос на /api/v1/admin/config с заголовком X-Admin: true",
		Explanation: `
			<h3>Проблема</h3>
			<p>Админские права проверяются через HTTP заголовки, которые можно легко подделать.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AdminConfig(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Проверка админ прав через заголовок, который можно подделать
    if r.Header.Get("X-Admin") == "true" || r.Header.Get("X-User-Role") == "admin" {
        sendJSON(w, map[string]interface{}{"config": config})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>HTTP заголовки контролируются клиентом и могут быть легко подделаны. Злоумышленник может добавить заголовок <code>X-Admin: true</code> к любому запросу и получить админский доступ.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AdminConfig(w http.ResponseWriter, r *http.Request) {
    // Получаем пользователя из сессии/токена
    user := getCurrentUser(r)
    
    // ПРОВЕРКА: Проверяем роль из серверной сессии, а не из заголовков
    if user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/admin/config" target="_blank" class="api-endpoint">/api/v1/admin/config</a></p>
				<p>Используйте curl или расширение браузера для добавления заголовка.</p>
				<form method="GET" action="/challenge/a01/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой заголовок вы использовали? (например: X-Admin)</label>
						<input type="text" name="header" placeholder="например: X-Admin" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			header := strings.ToLower(r.URL.Query().Get("header"))
			return strings.Contains(header, "admin") || strings.Contains(header, "x-admin")
		},
	}
	
	challenges["a01_7"] = Challenge{
		Title:       "CORS misconfiguration",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Сложный",
		Description: "CORS настроен так, что разрешает запросы с любого домена.",
		Task:        "Получите данные пользователя через CORS запрос с внешнего домена.",
		Hint:        "💡 Попробуйте отправить запрос на /api/v1/user/profile с заголовком Origin: http://evil.com",
		Explanation: `
			<h3>Проблема</h3>
			<p>CORS настроен так, что разрешает запросы с любого домена, что позволяет внешним сайтам делать запросы к API.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UserProfile(w http.ResponseWriter, r *http.Request) {
    origin := r.Header.Get("Origin")
    
    // УЯЗВИМОСТЬ: Разрешаем CORS для любого домена
    if origin != "" {
        w.Header().Set("Access-Control-Allow-Origin", origin)
        w.Header().Set("Access-Control-Allow-Credentials", "true")
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код разрешает CORS запросы с любого домена, указанного в заголовке Origin. Это позволяет злоумышленнику создать сайт на внешнем домене, который сможет делать запросы к API и получать данные пользователя.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UserProfile(w http.ResponseWriter, r *http.Request) {
    origin := r.Header.Get("Origin")
    
    // ПРОВЕРКА: Разрешаем только доверенные домены
    allowedOrigins := []string{"https://ourdomain.com", "https://app.ourdomain.com"}
    if contains(allowedOrigins, origin) {
        w.Header().Set("Access-Control-Allow-Origin", origin)
        w.Header().Set("Access-Control-Allow-Credentials", "true")
    }
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/user/profile" target="_blank" class="api-endpoint">/api/v1/user/profile</a></p>
				<form method="GET" action="/challenge/a01/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой внешний домен вы использовали в Origin? (например: evil.com)</label>
						<input type="text" name="origin" placeholder="например: evil.com" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			origin := r.URL.Query().Get("origin")
			return len(origin) > 0 && !strings.Contains(origin, "localhost")
		},
	}
	
	challenges["a01_8"] = Challenge{
		Title:       "Race condition",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Сложный",
		Description: "При переводе денег нет блокировки, можно отправить несколько запросов одновременно.",
		Task:        "Отправьте 3 одновременных запроса на перевод денег (симулируйте race condition).",
		Hint:        "💡 Попробуйте быстро отправить несколько POST запросов на /api/v1/payment/transfer одновременно.",
		Explanation: `
			<h3>Проблема</h3>
			<p>При переводе денег нет блокировки, можно отправить несколько запросов одновременно, что может привести к race condition и неправильному списанию средств.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PaymentTransferRace(w http.ResponseWriter, r *http.Request) {
    amount, _ := strconv.Atoi(r.FormValue("amount"))
    toUser := r.FormValue("to_user")
    
    // УЯЗВИМОСТЬ: Нет блокировки, можно отправить несколько запросов одновременно
    sendJSON(w, map[string]interface{}{
        "status":  "success",
        "message": fmt.Sprintf("Transferred %d to user %s", amount, toUser),
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не использует транзакции или блокировки при обработке переводов. Если злоумышленник отправит несколько запросов одновременно, все они могут быть обработаны, что приведет к неправильному списанию средств.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PaymentTransferRace(w http.ResponseWriter, r *http.Request) {
    amount, _ := strconv.Atoi(r.FormValue("amount"))
    toUser := r.FormValue("to_user")
    
    // ПРОВЕРКА: Используем транзакцию для атомарности
    tx, _ := db.Begin()
    defer tx.Rollback()
    
    // Блокируем строку для чтения/записи
    var balance int
    tx.QueryRow("SELECT balance FROM accounts WHERE user_id = $1 FOR UPDATE", userID).Scan(&balance)
    
    if balance < amount {
        http.Error(w, "Insufficient funds", http.StatusBadRequest)
        return
    }
    
    // Выполняем перевод
    tx.Exec("UPDATE accounts SET balance = balance - $1 WHERE user_id = $2", amount, userID)
    tx.Exec("UPDATE accounts SET balance = balance + $1 WHERE user_id = $2", amount, toUser)
    
    tx.Commit()
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/payment/transfer" target="_blank" class="api-endpoint">/api/v1/payment/transfer</a></p>
				<form method="GET" action="/challenge/a01/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Сколько одновременных запросов вы отправили? (минимум 3)</label>
						<input type="number" name="requests" placeholder="например: 3" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			reqs := r.URL.Query().Get("requests")
			return reqs >= "3"
		},
	}
	
	challenges["a01_9"] = Challenge{
		Title:       "Прямой доступ к админ панели",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Легкий",
		Description: "Админ панель доступна без проверки сессии, достаточно знать URL.",
		Task:        "Откройте админ панель напрямую по URL без авторизации.",
		Hint:        "💡 Попробуйте открыть /api/v1/admin/dashboard напрямую в браузере.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Админ панель доступна без проверки сессии, достаточно знать URL.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AdminDashboard(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Нет проверки сессии, достаточно знать URL
    html := renderPage("Admin Dashboard", "...")
    w.Write([]byte(html))
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет, авторизован ли пользователь и имеет ли он админские права. Любой, кто знает URL админ панели, может получить к ней доступ.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AdminDashboard(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Проверяем авторизацию и права
    user := getCurrentUser(r)
    if user == nil {
        http.Redirect(w, r, "/login", http.StatusUnauthorized)
        return
    }
    
    if user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    html := renderPage("Admin Dashboard", "...")
    w.Write([]byte(html))
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/admin/dashboard" target="_blank" class="api-endpoint">/api/v1/admin/dashboard</a></p>
				<form method="GET" action="/challenge/a01/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Вы смогли открыть админ панель? (напишите: yes или да)</label>
						<input type="text" name="accessed" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			accessed := strings.ToLower(r.URL.Query().Get("accessed"))
			return accessed == "yes" || accessed == "да" || accessed == "y"
		},
	}
	
	challenges["a01_10"] = Challenge{
		Title:       "Обход через параметр bypass_auth",
		Category:    "A01: Broken Access Control",
		Difficulty:  "Средний",
		Description: "В production есть параметр для обхода авторизации (оставлен для отладки).",
		Task:        "Получите настройки пользователя, используя параметр bypass_auth.",
		Hint:        "💡 Попробуйте добавить параметр bypass_auth=true к URL /api/v1/user/settings",
		Explanation: `
			<h3>Проблема</h3>
			<p>В production есть параметр для обхода авторизации (оставлен для отладки), который позволяет получить доступ без проверки.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UserSettings(w http.ResponseWriter, r *http.Request) {
    bypass := r.URL.Query().Get("bypass_auth")
    
    // УЯЗВИМОСТЬ: Параметр для обхода авторизации в production
    if bypass == "true" || r.URL.Query().Get("debug") == "1" {
        sendJSON(w, map[string]interface{}{"settings": settings})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>В коде остались параметры для отладки, которые позволяют обойти авторизацию. Эти параметры не должны быть доступны в production окружении.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UserSettings(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Всегда проверяем авторизацию
    user := getCurrentUser(r)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    // Удаляем все параметры обхода из production кода
    // Используем только проверку через сессию/токен
    
    sendJSON(w, map[string]interface{}{"settings": user.Settings})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/user/settings?bypass_auth=true" target="_blank" class="api-endpoint">/api/v1/user/settings?bypass_auth=true</a></p>
				<form method="GET" action="/challenge/a01/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой параметр вы использовали? (например: bypass_auth)</label>
						<input type="text" name="param" placeholder="например: bypass_auth" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			param := strings.ToLower(r.URL.Query().Get("param"))
			return strings.Contains(param, "bypass") || strings.Contains(param, "debug")
		},
	}
	
	// A02: Остальные задания (3-10)
	challenges["a02_3"] = Challenge{
		Title:       "Открытый доступ к метрикам",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Средний",
		Description: "Prometheus метрики доступны без аутентификации, раскрывая внутреннюю статистику.",
		Task:        "Получите доступ к метрикам приложения и найдите информацию об использовании API ключей.",
		Hint:        "💡 Попробуйте открыть /metrics напрямую в браузере.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Prometheus метрики доступны без аутентификации, раскрывая внутреннюю статистику и использование API ключей.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Metrics(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Prometheus метрики доступны без аутентификации
    w.Write([]byte("http_requests_total{method=\"GET\"} 123456\napi_keys_used{key=\"sk_live_abc123\"} 1234"))
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Метрики мониторинга не защищены аутентификацией, что позволяет злоумышленнику получить информацию о внутренней работе системы, включая использование API ключей и статистику запросов.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Metrics(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Требуем аутентификацию
    user := getCurrentUser(r)
    if user == nil || user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/metrics" target="_blank" class="api-endpoint">/metrics</a></p>
				<form method="GET" action="/challenge/a02/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой API ключ вы нашли в метриках? (напишите первые 10 символов)</label>
						<input type="text" name="api_key" placeholder="например: sk_live_abc" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			key := r.URL.Query().Get("api_key")
			return strings.Contains(key, "sk_live") || strings.Contains(key, "api_keys_used")
		},
	}
	
	challenges["a02_4"] = Challenge{
		Title:       "Открытый Git репозиторий",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Средний",
		Description: "Директория .git доступна через веб-сервер, раскрывая исходный код.",
		Task:        "Получите доступ к файлу .git/config и найдите URL репозитория.",
		Hint:        "💡 Попробуйте открыть /.git/config напрямую в браузере.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Директория .git доступна через веб-сервер, раскрывая исходный код и историю коммитов.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1GitConfig(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: .git директория доступна через веб-сервер
    w.Write([]byte("[remote \"origin\"]\nurl = https://github.com/company/production-app.git"))
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Веб-сервер настроен так, что отдает файлы из корневой директории, включая .git директорию. Это позволяет злоумышленнику получить доступ к исходному коду и истории коммитов.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>// Настройте веб-сервер так, чтобы он блокировал доступ к .git
// В nginx:
// location ~ /\\.git {
//     deny all;
// }
// Или используйте .gitignore и не загружайте .git на production сервер
</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/.git/config" target="_blank" class="api-endpoint">/.git/config</a></p>
				<form method="GET" action="/challenge/a02/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой URL репозитория вы нашли? (напишите: github.com или git)</label>
						<input type="text" name="repo_url" placeholder="например: github.com" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			url := strings.ToLower(r.URL.Query().Get("repo_url"))
			return strings.Contains(url, "github") || strings.Contains(url, "git")
		},
	}
	
	challenges["a02_5"] = Challenge{
		Title:       "Слабая конфигурация CORS",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Сложный",
		Description:    "CORS разрешен для всех доменов (*), что позволяет делать запросы с любого сайта.",
		Task:        "Получите данные через CORS запрос, используя внешний домен в Origin.",
		Hint:        "💡 Попробуйте отправить запрос на /api/v1/api/data с заголовком Origin: http://evil.com",
		Explanation: `
			<h3>Проблема</h3>
			<p>CORS разрешен для всех доменов (*), что позволяет делать запросы с любого сайта.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ApiData(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: CORS разрешен для всех доменов
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
    sendJSON(w, map[string]interface{}{"api_key": "sk_live_1234567890"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код разрешает CORS запросы с любого домена, указанного в заголовке Origin. Это позволяет злоумышленнику создать сайт на внешнем домене, который сможет делать запросы к API и получать данные.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1ApiData(w http.ResponseWriter, r *http.Request) {
    origin := r.Header.Get("Origin")
    
    // ПРОВЕРКА: Разрешаем только доверенные домены
    allowedOrigins := []string{"https://ourdomain.com", "https://app.ourdomain.com"}
    if contains(allowedOrigins, origin) {
        w.Header().Set("Access-Control-Allow-Origin", origin)
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
    }
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/api/data" target="_blank" class="api-endpoint">/api/v1/api/data</a></p>
				<form method="GET" action="/challenge/a02/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой внешний домен вы использовали? (например: evil.com)</label>
						<input type="text" name="domain" placeholder="например: evil.com" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			domain := r.URL.Query().Get("domain")
			return len(domain) > 0 && !strings.Contains(domain, "localhost")
		},
	}
	
	challenges["a02_6"] = Challenge{
		Title:       "Версия в заголовках",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Легкий",
		Description: "В HTTP заголовках раскрываются версии всех используемых технологий.",
		Task:        "Получите информацию о версиях технологий из заголовков ответа.",
		Hint:        "💡 Откройте /api/v1/health и посмотрите заголовки ответа (X-Powered-By, Server и т.д.)",
		Explanation: `
			<h3>Проблема</h3>
			<p>В HTTP заголовках раскрываются версии всех используемых технологий (фреймворки, базы данных, веб-серверы), что помогает злоумышленнику найти известные уязвимости для этих версий.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Health(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Раскрываем версии технологий
    w.Header().Set("Server", "nginx/1.18.0")
    w.Header().Set("X-Powered-By", "Express/4.17.1")
    w.Header().Set("X-Framework", "Spring Boot 2.5.0")
    w.Header().Set("X-Database", "PostgreSQL 13.2")
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Заголовки Server, X-Powered-By и другие часто устанавливаются автоматически фреймворками и веб-серверами. Это раскрывает информацию о технологиях и их версиях, что помогает злоумышленнику найти известные CVE уязвимости.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Health(w http.ResponseWriter, r *http.Request) {
    // УДАЛЯЕМ или скрываем заголовки с версиями
    // Не устанавливаем X-Powered-By, X-Framework и т.д.
    // В nginx можно скрыть Server заголовок:
    // server_tokens off;
    
    sendJSON(w, map[string]interface{}{
        "status": "healthy",
        // Не раскрываем версию приложения
    })
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/health" target="_blank" class="api-endpoint">/api/v1/health</a></p>
				<p>Откройте DevTools (F12) и посмотрите заголовки ответа.</p>
				<form method="GET" action="/challenge/a02/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая версия фреймворка указана в заголовках? (напишите: Spring Boot или Express)</label>
						<input type="text" name="framework" placeholder="например: Spring Boot" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			framework := strings.ToLower(r.URL.Query().Get("framework"))
			return strings.Contains(framework, "spring") || strings.Contains(framework, "express")
		},
	}
	
	challenges["a02_7"] = Challenge{
		Title:       "Небезопасные настройки сессий",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Средний",
		Description: "Сессия создается без флагов HttpOnly и Secure, что делает её уязвимой для XSS и перехвата.",
		Task:        "Получите сессию и проверьте, что она не имеет флагов HttpOnly и Secure.",
		Hint:        "💡 Откройте /api/v1/auth/session и посмотрите заголовки Set-Cookie в ответе.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Сессия создается без флагов HttpOnly и Secure, что делает её уязвимой для XSS атак и перехвата через незащищенные соединения.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthSession(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Сессия без HttpOnly и Secure флагов
    w.Header().Set("Set-Cookie", "session=abc123def456; Path=/")
    w.Header().Set("Set-Cookie", "user_id=123; Path=/")
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Без флага HttpOnly JavaScript может получить доступ к cookie, что делает сессию уязвимой для XSS атак. Без флага Secure cookie передается по HTTP, что позволяет перехватить её через незащищенные соединения.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthSession(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Устанавливаем HttpOnly и Secure флаги
    w.Header().Set("Set-Cookie", "session=abc123def456; Path=/; HttpOnly; Secure; SameSite=Strict")
    w.Header().Set("Set-Cookie", "user_id=123; Path=/; HttpOnly; Secure; SameSite=Strict")
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/session" target="_blank" class="api-endpoint">/api/v1/auth/session</a></p>
				<form method="GET" action="/challenge/a02/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой ID сессии вы получили? (первые 6 символов)</label>
						<input type="text" name="session_id" placeholder="например: abc123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sessionID := r.URL.Query().Get("session_id")
			return len(sessionID) >= 3
		},
	}
	
	challenges["a02_8"] = Challenge{
		Title:       "Открытый доступ к backup файлам",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Средний",
		Description: "Backup файлы доступны через веб-сервер без аутентификации.",
		Task:        "Получите доступ к backup файлу database_backup_2024.sql.",
		Hint:        "💡 Попробуйте запросить /api/v1/backup?file=database_backup_2024.sql",
		Explanation: `
			<h3>Проблема</h3>
			<p>Backup файлы доступны через веб-сервер без аутентификации, что позволяет злоумышленнику получить полную копию базы данных с паролями и чувствительными данными.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Backup(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    
    // УЯЗВИМОСТЬ: Backup файлы доступны через веб
    if file == "database_backup_2024.sql" {
        w.Write([]byte("-- Database backup\nINSERT INTO users VALUES (1, 'admin', 'password123');"))
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Backup файлы хранятся в директории, доступной через веб-сервер, или есть эндпоинт для их скачивания без проверки прав доступа. Это позволяет злоумышленнику получить полную копию базы данных.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Backup(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Требуем аутентификацию и админские права
    user := getCurrentUser(r)
    if user == nil || user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // Храним backup файлы вне публичной директории
    // Или используем безопасное хранилище (S3 с ограниченным доступом)
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/backup?file=database_backup_2024.sql" target="_blank" class="api-endpoint">/api/v1/backup?file=database_backup_2024.sql</a></p>
				<form method="GET" action="/challenge/a02/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой файл вы получили? (напишите имя файла)</label>
						<input type="text" name="file" placeholder="например: database_backup_2024.sql" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			file := strings.ToLower(r.URL.Query().Get("file"))
			return strings.Contains(file, "backup") || strings.Contains(file, "database")
		},
	}
	
	challenges["a02_9"] = Challenge{
		Title:       "Открытый доступ к логам",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Средний",
		Description: "Логи приложения доступны без аутентификации, раскрывая чувствительную информацию.",
		Task:        "Получите доступ к логам и найдите JWT токен или пароль в них.",
		Hint:        "💡 Попробуйте открыть /api/v1/logs напрямую в браузере.",
		Explanation: `
			<h3>Проблема</h3>
			<p>Логи приложения доступны без аутентификации, раскрывая чувствительную информацию (JWT токены, пароли, API ключи, SQL запросы).</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Logs(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Логи доступны без аутентификации
    w.Write([]byte("2024-01-15 [INFO] User login: admin@company.com\n2024-01-15 [DEBUG] JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."))
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Логи хранятся в файлах, доступных через веб-сервер, или есть эндпоинт для их просмотра без проверки прав доступа. Это позволяет злоумышленнику получить доступ к чувствительной информации, которая была залогирована.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Logs(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Требуем аутентификацию и админские права
    user := getCurrentUser(r)
    if user == nil || user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // Храним логи вне публичной директории
    // Используем централизованное логирование (ELK, Splunk)
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/logs" target="_blank" class="api-endpoint">/api/v1/logs</a></p>
				<form method="GET" action="/challenge/a02/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая чувствительная информация была в логах? (напишите: JWT или password)</label>
						<input type="text" name="sensitive" placeholder="например: JWT" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sensitive := strings.ToLower(r.URL.Query().Get("sensitive"))
			return strings.Contains(sensitive, "jwt") || strings.Contains(sensitive, "password") || strings.Contains(sensitive, "token")
		},
	}
	
	challenges["a02_10"] = Challenge{
		Title:       "Конфигурация базы данных в открытом виде",
		Category:    "A02: Security Misconfiguration",
		Difficulty:  "Сложный",
		Description: "Конфигурация базы данных доступна через API, раскрывая пароли и хосты.",
		Task:        "Получите конфигурацию базы данных и найдите пароль администратора БД.",
		Hint:        "💡 Попробуйте запросить /api/v1/config/database",
		Explanation: `
			<h3>Проблема</h3>
			<p>Конфигурация базы данных доступна через API, раскрывая пароли, хосты и другие чувствительные данные.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ConfigDatabase(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Конфигурация БД доступна через API
    sendJSON(w, map[string]interface{}{
        "database": map[string]string{
            "host":     "prod-db.internal.company.com",
            "port":     "5432",
            "username": "db_admin",
            "password": "SuperSecretDBPassword123",
        },
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Эндпоинт для просмотра конфигурации не защищен аутентификацией или доступен для всех пользователей. Это позволяет злоумышленнику получить полную конфигурацию базы данных, включая пароли и хосты.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1ConfigDatabase(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Требуем аутентификацию и админские права
    user := getCurrentUser(r)
    if user == nil || user.Role != "admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // НЕ показываем пароли и чувствительные данные
    // Используем переменные окружения или секретные менеджеры
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/config/database" target="_blank" class="api-endpoint">/api/v1/config/database</a></p>
				<form method="GET" action="/challenge/a02/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пароль БД вы нашли? (первые 10 символов)</label>
						<input type="text" name="db_password" placeholder="например: SuperSecret" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pass := r.URL.Query().Get("db_password")
			return strings.Contains(pass, "SuperSecret") || strings.Contains(pass, "Password") || len(pass) >= 5
		},
	}
	
	// A03: Все задания (1-10)
	challenges["a03_1"] = Challenge{
		Title:       "Установка пакетов без проверки",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Средний",
		Description: "Пакеты устанавливаются без проверки подписи и целостности.",
		Task:        "Установите пакет через API без проверки подписи.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/packages/install с параметром package",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пакеты устанавливаются без проверки цифровой подписи и целостности, что позволяет установить поддельный или модифицированный пакет.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PackagesInstall(w http.ResponseWriter, r *http.Request) {
    packageName := r.FormValue("package")
    
    // УЯЗВИМОСТЬ: Устанавливаем пакет без проверки подписи
    sendJSON(w, map[string]interface{}{
        "message": fmt.Sprintf("Package %s installed without signature verification", packageName),
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет цифровую подпись пакета перед установкой. Это позволяет злоумышленнику создать поддельный пакет с вредоносным кодом и установить его в систему.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PackagesInstall(w http.ResponseWriter, r *http.Request) {
    packageName := r.FormValue("package")
    
    // ПРОВЕРКА: Проверяем подпись пакета
    packageData, signature := downloadPackage(packageName)
    if !verifySignature(packageData, signature) {
        http.Error(w, "Invalid package signature", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем checksum
    if !verifyChecksum(packageData) {
        http.Error(w, "Package integrity check failed", http.StatusBadRequest)
        return
    }
    
    // Только после проверки устанавливаем
    installPackage(packageData)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/packages/install" target="_blank" class="api-endpoint">/api/v1/packages/install</a></p>
				<form method="GET" action="/challenge/a03/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пакет вы установили? (например: lodash)</label>
						<input type="text" name="package" placeholder="например: lodash" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pkg := r.URL.Query().Get("package")
			return len(pkg) > 0
		},
	}
	
	challenges["a03_2"] = Challenge{
		Title:       "Загрузка зависимостей из небезопасных источников",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Сложный",
		Description: "Зависимости загружаются с любого URL без проверки.",
		Task:        "Загрузите зависимость с произвольного URL (например, http://evil.com/malware.js).",
		Hint:        "💡 Попробуйте запросить /api/v1/dependencies/update?url=http://evil.com/malware.js",
		Explanation: `
			<h3>Проблема</h3>
			<p>Зависимости загружаются с любого URL без проверки, что позволяет загрузить вредоносный код с внешнего сервера.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1DependenciesUpdate(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    
    // УЯЗВИМОСТЬ: Загружаем с любого URL без проверки
    downloadAndInstall(url)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет источник загрузки зависимостей. Злоумышленник может указать URL на свой сервер и загрузить вредоносный код в систему.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1DependenciesUpdate(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    
    // ПРОВЕРКА: Разрешаем только доверенные источники
    allowedSources := []string{"https://registry.npmjs.org", "https://pypi.org"}
    if !isAllowedSource(url, allowedSources) {
        http.Error(w, "Untrusted source", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем подпись и checksum
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/dependencies/update" target="_blank" class="api-endpoint">/api/v1/dependencies/update</a></p>
				<form method="GET" action="/challenge/a03/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой URL вы использовали? (напишите: evil.com или внешний домен)</label>
						<input type="text" name="url" placeholder="например: evil.com" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			url := r.URL.Query().Get("url")
			return len(url) > 0 && !strings.Contains(url, "localhost")
		},
	}
	
	challenges["a03_3"] = Challenge{
		Title:       "Выполнение произвольного кода",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Сложный",
		Description: "Произвольные команды выполняются через npm scripts без проверки.",
		Task:        "Выполните произвольную команду через API (например, ls или whoami).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/build с параметром script",
		Explanation: `
			<h3>Проблема</h3>
			<p>Произвольные команды выполняются через npm scripts без проверки, что позволяет выполнить любой системный код.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Build(w http.ResponseWriter, r *http.Request) {
    script := r.FormValue("script")
    
    // УЯЗВИМОСТЬ: Выполняем произвольную команду
    exec.Command("sh", "-c", script).Output()
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код выполняет команды напрямую из пользовательского ввода без валидации. Это позволяет злоумышленнику выполнить любую системную команду, включая удаление файлов, чтение конфигурации и т.д.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Build(w http.ResponseWriter, r *http.Request) {
    script := r.FormValue("script")
    
    // ПРОВЕРКА: Разрешаем только безопасные скрипты
    allowedScripts := []string{"build", "test", "lint"}
    if !contains(allowedScripts, script) {
        http.Error(w, "Script not allowed", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Используем whitelist команд, не выполняем произвольный код
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/build" target="_blank" class="api-endpoint">/api/v1/build</a></p>
				<form method="GET" action="/challenge/a03/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какую команду вы выполнили? (например: ls или whoami)</label>
						<input type="text" name="command" placeholder="например: ls" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			cmd := r.URL.Query().Get("command")
			return len(cmd) > 0
		},
	}
	
	challenges["a03_4"] = Challenge{
		Title:       "Обновление без проверки checksum",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Средний",
		Description: "Обновление выполняется без проверки checksum файла.",
		Task:        "Обновите приложение до версии 2.0.0 без проверки целостности.",
		Hint:        "💡 Попробуйте запросить /api/v1/update?version=2.0.0",
		Explanation: `
			<h3>Проблема</h3>
			<p>Обновление выполняется без проверки checksum файла, что позволяет установить модифицированную версию.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Update(w http.ResponseWriter, r *http.Request) {
    version := r.URL.Query().Get("version")
    
    // УЯЗВИМОСТЬ: Обновляем без проверки checksum
    downloadAndInstall(version)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет целостность файла обновления перед установкой. Это позволяет злоумышленнику подменить файл обновления и установить модифицированную версию с вредоносным кодом.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Update(w http.ResponseWriter, r *http.Request) {
    version := r.URL.Query().Get("version")
    
    // ПРОВЕРКА: Проверяем checksum
    fileData := downloadUpdate(version)
    expectedChecksum := getExpectedChecksum(version)
    if calculateSHA256(fileData) != expectedChecksum {
        http.Error(w, "Checksum mismatch", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем подпись
    if !verifySignature(fileData) {
        http.Error(w, "Invalid signature", http.StatusBadRequest)
        return
    }
    
    // Только после проверки устанавливаем
    installUpdate(fileData)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/update?version=2.0.0" target="_blank" class="api-endpoint">/api/v1/update?version=2.0.0</a></p>
				<form method="GET" action="/challenge/a03/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>До какой версии вы обновили? (например: 2.0.0)</label>
						<input type="text" name="version" placeholder="например: 2.0.0" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			version := r.URL.Query().Get("version")
			return len(version) > 0
		},
	}
	
	challenges["a03_5"] = Challenge{
		Title:       "Устаревшие библиотеки с уязвимостями",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Легкий",
		Description: "Используются библиотеки с известными CVE уязвимостями.",
		Task:        "Получите список зависимостей и найдите библиотеку с CVE.",
		Hint:        "💡 Попробуйте запросить /api/v1/dependencies/list",
		Explanation: `
			<h3>Проблема</h3>
			<p>Используются библиотеки с известными CVE уязвимостями, которые не обновляются.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1DependenciesList(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Используем устаревшие библиотеки с CVE
    dependencies := map[string]string{
        "express": "4.17.1", // CVE-2022-24999
        "lodash": "4.17.20", // CVE-2021-23337
    }
    sendJSON(w, map[string]interface{}{"dependencies": dependencies})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Зависимости не обновляются регулярно, и не проверяются на наличие известных уязвимостей. Это позволяет злоумышленнику использовать известные CVE для атаки на систему.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>// Используйте инструменты для проверки уязвимостей:
// - npm audit
// - Snyk
// - Dependabot
// - OWASP Dependency-Check

// Автоматически обновляйте зависимости
// Используйте автоматические обновления безопасности
// Настройте CI/CD для проверки уязвимостей
</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/dependencies/list" target="_blank" class="api-endpoint">/api/v1/dependencies/list</a></p>
				<form method="GET" action="/challenge/a03/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая библиотека с CVE вы нашли? (например: express или lodash)</label>
						<input type="text" name="library" placeholder="например: express" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			lib := strings.ToLower(r.URL.Query().Get("library"))
			return strings.Contains(lib, "express") || strings.Contains(lib, "lodash") || strings.Contains(lib, "axios")
		},
	}
	
	challenges["a03_6"] = Challenge{
		Title:       "Typosquatting",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Средний",
		Description: "Принимаются похожие имена пакетов (typosquatting атака).",
		Task:        "Установите пакет с опечаткой в имени (например, expres вместо express).",
		Hint:        "💡 Попробуйте запросить /api/v1/packages/search?q=expres",
		Explanation: `
			<h3>Проблема</h3>
			<p>Принимаются похожие имена пакетов (typosquatting атака), что позволяет установить поддельный пакет.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PackagesSearch(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // УЯЗВИМОСТЬ: Принимаем похожие имена без проверки
    if query == "expres" { // опечатка в "express"
        sendJSON(w, map[string]interface{}{"package": "expres", "version": "1.0.0"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет, является ли имя пакета официальным или поддельным. Злоумышленник может создать пакет с похожим именем (typosquatting) и установить его вместо оригинального.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PackagesSearch(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // ПРОВЕРКА: Проверяем, что пакет официальный
    if !isOfficialPackage(query) {
        http.Error(w, "Package not found or not official", http.StatusNotFound)
        return
    }
    
    // ПРОВЕРКА: Предупреждаем о похожих именах
    if hasTypoSquatting(query) {
        http.Error(w, "Possible typo, did you mean 'express'?", http.StatusBadRequest)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/packages/search?q=expres" target="_blank" class="api-endpoint">/api/v1/packages/search?q=expres</a></p>
				<form method="GET" action="/challenge/a03/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какое имя пакета с опечаткой вы использовали? (например: expres)</label>
						<input type="text" name="package" placeholder="например: expres" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pkg := strings.ToLower(r.URL.Query().Get("package"))
			return strings.Contains(pkg, "expres") || strings.Contains(pkg, "typosquat")
		},
	}
	
	challenges["a03_7"] = Challenge{
		Title:       "Компрометированный репозиторий",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Сложный",
		Description: "Репозиторий клонируется без проверки подписи коммитов.",
		Task:        "Клонируйте репозиторий без проверки подписи коммитов.",
		Hint:        "💡 Попробуйте запросить /api/v1/repo/clone?repo=https://github.com/evil/repo",
		Explanation: `
			<h3>Проблема</h3>
			<p>Репозиторий клонируется без проверки подписи коммитов, что позволяет установить код с непроверенными изменениями.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1RepoClone(w http.ResponseWriter, r *http.Request) {
    repo := r.URL.Query().Get("repo")
    
    // УЯЗВИМОСТЬ: Клонируем без проверки подписи коммитов
    exec.Command("git", "clone", repo).Run()
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код клонирует репозиторий без проверки GPG подписи коммитов. Это позволяет установить код с непроверенными или подделанными изменениями.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1RepoClone(w http.ResponseWriter, r *http.Request) {
    repo := r.URL.Query().Get("repo")
    
    // ПРОВЕРКА: Проверяем подпись коммитов
    exec.Command("git", "clone", repo).Run()
    exec.Command("git", "verify-commit", "HEAD").Run()
    
    // ПРОВЕРКА: Проверяем, что репозиторий доверенный
    if !isTrustedRepository(repo) {
        http.Error(w, "Untrusted repository", http.StatusBadRequest)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/repo/clone" target="_blank" class="api-endpoint">/api/v1/repo/clone</a></p>
				<form method="GET" action="/challenge/a03/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой репозиторий вы клонировали? (напишите: github.com или repo)</label>
						<input type="text" name="repo" placeholder="например: github.com" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			repo := strings.ToLower(r.URL.Query().Get("repo"))
			return strings.Contains(repo, "github") || strings.Contains(repo, "repo")
		},
	}
	
	challenges["a03_8"] = Challenge{
		Title:       "Небезопасное обновление через webhook",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Сложный",
		Description: "Код обновляется из webhook без проверки подписи.",
		Task:        "Отправьте POST запрос на webhook для обновления кода без проверки подписи.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/webhook/update",
		Explanation: `
			<h3>Проблема</h3>
			<p>Код обновляется из webhook без проверки подписи, что позволяет злоумышленнику обновить код через поддельный webhook.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1WebhookUpdate(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Обновляем код без проверки подписи webhook
    if r.Method == "POST" {
        pullLatestCode()
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Webhook не проверяет подпись запроса (например, GitHub webhook signature). Это позволяет злоумышленнику отправить поддельный webhook и обновить код в системе.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1WebhookUpdate(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Проверяем подпись webhook
    signature := r.Header.Get("X-Hub-Signature-256")
    body, _ := ioutil.ReadAll(r.Body)
    
    expectedSignature := calculateHMAC(body, webhookSecret)
    if signature != expectedSignature {
        http.Error(w, "Invalid webhook signature", http.StatusUnauthorized)
        return
    }
    
    // Только после проверки обновляем
    pullLatestCode()
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/webhook/update" target="_blank" class="api-endpoint">/api/v1/webhook/update</a></p>
				<form method="GET" action="/challenge/a03/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Вы отправили POST запрос? (напишите: yes или да)</label>
						<input type="text" name="sent" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sent := strings.ToLower(r.URL.Query().Get("sent"))
			return sent == "yes" || sent == "да" || sent == "y"
		},
	}
	
	challenges["a03_9"] = Challenge{
		Title:       "Подмена зависимостей через DNS",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Сложный",
		Description: "Пакеты загружаются без проверки DNS и репозитория.",
		Task:        "Загрузите пакет без проверки DNS (симулируйте подмену DNS).",
		Hint:        "💡 Попробуйте запросить /api/v1/package/registry?package=malicious-package",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пакеты загружаются без проверки DNS и репозитория, что позволяет подменить пакет через DNS spoofing.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PackageRegistry(w http.ResponseWriter, r *http.Request) {
    packageName := r.URL.Query().Get("package")
    
    // УЯЗВИМОСТЬ: Загружаем без проверки DNS
    url := fmt.Sprintf("http://registry.npmjs.org/%s", packageName)
    downloadPackage(url)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код использует HTTP вместо HTTPS или не проверяет сертификат DNS. Это позволяет злоумышленнику подменить DNS и загрузить вредоносный пакет вместо оригинального.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PackageRegistry(w http.ResponseWriter, r *http.Request) {
    packageName := r.URL.Query().Get("package")
    
    // ПРОВЕРКА: Используем HTTPS и проверяем сертификат
    url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
    
    // ПРОВЕРКА: Проверяем DNS через DNSSEC
    // ПРОВЕРКА: Проверяем подпись пакета
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/package/registry" target="_blank" class="api-endpoint">/api/v1/package/registry</a></p>
				<form method="GET" action="/challenge/a03/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пакет вы загрузили? (например: malicious-package)</label>
						<input type="text" name="package" placeholder="например: malicious-package" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pkg := r.URL.Query().Get("package")
			return len(pkg) > 0
		},
	}
	
	challenges["a03_10"] = Challenge{
		Title:       "Транзитивные зависимости с уязвимостями",
		Category:    "A03: Software Supply Chain Failures",
		Difficulty:  "Средний",
		Description: "Транзитивные зависимости содержат уязвимости, которые не проверяются.",
		Task:        "Получите дерево зависимостей и найдите транзитивную зависимость с CVE.",
		Hint:        "💡 Попробуйте запросить /api/v1/dependencies/tree",
		Explanation: `
			<h3>Проблема</h3>
			<p>Транзитивные зависимости содержат уязвимости, которые не проверяются, что создает скрытые риски безопасности.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1DependenciesTree(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Не проверяем транзитивные зависимости
    tree := getDependencyTree()
    sendJSON(w, map[string]interface{}{"tree": tree})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет транзитивные зависимости (зависимости зависимостей) на наличие уязвимостей. Это создает скрытые риски, так как уязвимость может быть в глубоко вложенной зависимости.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1DependenciesTree(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Проверяем все транзитивные зависимости
    tree := getDependencyTree()
    vulnerabilities := scanAllDependencies(tree)
    
    if len(vulnerabilities) > 0 {
        sendJSON(w, map[string]interface{}{
            "tree": tree,
            "vulnerabilities": vulnerabilities,
            "warning": "Found vulnerabilities in transitive dependencies",
        })
    }
    
    // Используйте инструменты: npm audit, Snyk, Dependabot
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/dependencies/tree" target="_blank" class="api-endpoint">/api/v1/dependencies/tree</a></p>
				<form method="GET" action="/challenge/a03/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Сколько всего уязвимостей найдено? (напишите число)</label>
						<input type="number" name="vulns" placeholder="например: 15" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			vulns := r.URL.Query().Get("vulns")
			return vulns == "15" || vulns >= "10"
		},
	}
	
	// A04: Остальные задания (3-10)
	challenges["a04_3"] = Challenge{
		Title:       "Использование SHA1 для подписи",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Средний",
		Description: "SHA1 используется для подписи данных, хотя алгоритм устарел и небезопасен.",
		Task:        "Создайте подпись данных используя SHA1 (устаревший алгоритм).",
		Hint:        "💡 Попробуйте запросить /api/v1/api/sign?data=test",
		Explanation: `
			<h3>Проблема</h3>
			<p>SHA1 используется для подписи данных, хотя алгоритм устарел и уязвим для коллизий.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ApiSign(w http.ResponseWriter, r *http.Request) {
    data := r.URL.Query().Get("data")
    
    // УЯЗВИМОСТЬ: Используем SHA1 для подписи (устарел)
    hash := sha1.Sum([]byte(data))
    sendJSON(w, map[string]interface{}{"signature": fmt.Sprintf("%x", hash)})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>SHA1 был разработан в 1995 году и сейчас считается небезопасным из-за возможности создания коллизий. Это позволяет создать два разных файла с одинаковой подписью.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1ApiSign(w http.ResponseWriter, r *http.Request) {
    data := r.URL.Query().Get("data")
    
    // ПРОВЕРКА: Используем современные алгоритмы (SHA-256, SHA-512, HMAC)
    h := hmac.New(sha256.New, []byte(secretKey))
    h.Write([]byte(data))
    signature := h.Sum(nil)
    
    sendJSON(w, map[string]interface{}{"signature": fmt.Sprintf("%x", signature)})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/api/sign?data=test" target="_blank" class="api-endpoint">/api/v1/api/sign?data=test</a></p>
				<form method="GET" action="/challenge/a04/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой алгоритм используется? (напишите: SHA1)</label>
						<input type="text" name="algorithm" placeholder="например: SHA1" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			algo := strings.ToLower(r.URL.Query().Get("algorithm"))
			return strings.Contains(algo, "sha1")
		},
	}
	
	challenges["a04_4"] = Challenge{
		Title:       "Слабый ключ шифрования",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Средний",
		Description: "Используется слабый ключ шифрования (короткий и простой).",
		Task:        "Зашифруйте данные и найдите длину ключа (должна быть очень короткой).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/encrypt с параметром data",
		Explanation: `
			<h3>Проблема</h3>
			<p>Используется слабый ключ шифрования (короткий и простой), который легко взломать через brute force.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Encrypt(w http.ResponseWriter, r *http.Request) {
    data := r.FormValue("data")
    key := "12345" // Слабый ключ
    
    // УЯЗВИМОСТЬ: Простое XOR шифрование с слабым ключом
    encrypted := make([]byte, len(data))
    for i := range data {
        encrypted[i] = data[i] ^ key[i%len(key)]
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Ключ слишком короткий (5 символов) и простой, что позволяет легко взломать его через brute force атаку. Современные стандарты требуют минимум 256 бит (32 байта) для симметричного шифрования.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Encrypt(w http.ResponseWriter, r *http.Request) {
    data := r.FormValue("data")
    
    // ПРОВЕРКА: Генерируем криптографически стойкий ключ
    key := make([]byte, 32) // 256 бит
    if _, err := rand.Read(key); err != nil {
        http.Error(w, "Key generation failed", http.StatusInternalServerError)
        return
    }
    
    // ПРОВЕРКА: Используем современные алгоритмы (AES-256-GCM)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    
    ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/encrypt" target="_blank" class="api-endpoint">/api/v1/encrypt</a></p>
				<form method="GET" action="/challenge/a04/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая длина ключа? (напишите число, должно быть маленьким)</label>
						<input type="number" name="key_length" placeholder="например: 5" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			length := r.URL.Query().Get("key_length")
			return length <= "10"
		},
	}
	
	challenges["a04_5"] = Challenge{
		Title:       "API ключи в открытом виде",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Легкий",
		Description: "API ключи захардкожены в коде и доступны через API.",
		Task:        "Получите список API ключей из конфигурации.",
		Hint:        "💡 Попробуйте запросить /api/v1/config/keys",
		Explanation: `
			<h3>Проблема</h3>
			<p>API ключи захардкожены в коде и доступны через API, что позволяет злоумышленнику получить их напрямую.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ConfigKeys(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: API ключи захардкожены в коде
    sendJSON(w, map[string]interface{}{
        "api_keys": map[string]string{
            "stripe_secret": "sk_live_51Hqw2LKD8vqX8Z4EXAMPLE",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        },
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>API ключи хранятся прямо в коде, что делает их доступными при утечке исходного кода или через эндпоинт конфигурации. Это критическая уязвимость, так как ключи можно использовать для доступа к внешним сервисам.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1ConfigKeys(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: НИКОГДА не возвращаем ключи через API
    // Храним ключи в переменных окружения или секретных менеджерах
    
    // Используем переменные окружения:
    // stripeKey := os.Getenv("STRIPE_SECRET_KEY")
    // awsKey := os.Getenv("AWS_ACCESS_KEY")
    
    // Или используем секретные менеджеры:
    // - AWS Secrets Manager
    // - HashiCorp Vault
    // - Azure Key Vault
    
    http.Error(w, "Access denied", http.StatusForbidden)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/config/keys" target="_blank" class="api-endpoint">/api/v1/config/keys</a></p>
				<form method="GET" action="/challenge/a04/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой API ключ вы нашли? (первые 10 символов, например: sk_live_51)</label>
						<input type="text" name="api_key" placeholder="например: sk_live_51" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			key := r.URL.Query().Get("api_key")
			return strings.Contains(key, "sk_live") || strings.Contains(key, "aws") || len(key) >= 5
		},
	}
	
	challenges["a04_6"] = Challenge{
		Title:       "Использование HTTP вместо HTTPS",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Легкий",
		Description: "Платежи обрабатываются через HTTP, передавая данные в открытом виде.",
		Task:        "Обработайте платеж через HTTP и убедитесь, что данные передаются без шифрования.",
		Hint:        "💡 Попробуйте запросить /api/v1/payment/process/http",
		Explanation: `
			<h3>Проблема</h3>
			<p>Платежи обрабатываются через HTTP, передавая данные в открытом виде, что позволяет перехватить их через MITM атаку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PaymentProcessHTTP(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Платежи обрабатываются через HTTP
    if r.TLS == nil {
        sendJSON(w, map[string]interface{}{
            "message": "Payment processed over HTTP (INSECURE!)",
            "warning": "Credit card data transmitted in plain text",
        })
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не требует использования HTTPS для обработки платежей. Это позволяет злоумышленнику перехватить данные платежей через MITM атаку или прослушивание сети.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PaymentProcessHTTP(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Требуем HTTPS для всех платежей
    if r.TLS == nil {
        http.Error(w, "HTTPS required for payment processing", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что используется TLS 1.2 или выше
    if r.TLS.Version < 0x0303 { // TLS 1.2
        http.Error(w, "TLS 1.2 or higher required", http.StatusForbidden)
        return
    }
    
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/payment/process/http" target="_blank" class="api-endpoint">/api/v1/payment/process/http</a></p>
				<form method="GET" action="/challenge/a04/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой протокол используется? (напишите: HTTP)</label>
						<input type="text" name="protocol" placeholder="например: HTTP" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			protocol := strings.ToLower(r.URL.Query().Get("protocol"))
			return strings.Contains(protocol, "http") && !strings.Contains(protocol, "https")
		},
	}
	
	challenges["a04_7"] = Challenge{
		Title:       "Слабая генерация токенов",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Средний",
		Description: "Токен генерируется на основе предсказуемых данных (время).",
		Task:        "Получите токен и убедитесь, что он предсказуем (основан на времени).",
		Hint:        "💡 Попробуйте запросить /api/v1/auth/token",
		Explanation: `
			<h3>Проблема</h3>
			<p>Токен генерируется на основе предсказуемых данных (время), что позволяет злоумышленнику предсказать или воссоздать токен.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthToken(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Токен генерируется на основе времени (предсказуемо)
    token := fmt.Sprintf("token_%s", r.Header.Get("Date"))
    
    sendJSON(w, map[string]interface{}{"token": token})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Токен генерируется на основе предсказуемых данных (время, дата), что позволяет злоумышленнику предсказать или воссоздать токен, зная время генерации.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthToken(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Используем криптографически стойкий генератор случайных чисел
    token := make([]byte, 32)
    if _, err := rand.Read(token); err != nil {
        http.Error(w, "Token generation failed", http.StatusInternalServerError)
        return
    }
    
    // Или используем UUID v4 или JWT с криптографически стойкой подписью
    tokenString := base64.URLEncoding.EncodeToString(token)
    sendJSON(w, map[string]interface{}{"token": tokenString})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/token" target="_blank" class="api-endpoint">/api/v1/auth/token</a></p>
				<form method="GET" action="/challenge/a04/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Токен предсказуем? (напишите: yes или да)</label>
						<input type="text" name="predictable" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pred := strings.ToLower(r.URL.Query().Get("predictable"))
			return pred == "yes" || pred == "да" || pred == "y"
		},
	}
	
	challenges["a04_8"] = Challenge{
		Title:       "Небезопасный обмен ключами",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Средний",
		Description: "Ключ отправляется в открытом виде без шифрования.",
		Task:        "Получите общий ключ, который передается в открытом виде.",
		Hint:        "💡 Попробуйте запросить /api/v1/key/exchange",
		Explanation: `
			<h3>Проблема</h3>
			<p>Ключ отправляется в открытом виде без шифрования, что позволяет перехватить его через MITM атаку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1KeyExchange(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Ключ отправляется в открытом виде
    sendJSON(w, map[string]interface{}{
        "shared_key": "abc123def456",
        "method": "Plain text key exchange (INSECURE!)",
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Ключ передается в открытом виде без использования протоколов безопасного обмена ключами (например, Diffie-Hellman). Это позволяет злоумышленнику перехватить ключ и использовать его для расшифровки данных.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1KeyExchange(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Используем протокол безопасного обмена ключами (Diffie-Hellman)
    // Или используем TLS для защиты передачи ключа
    
    // Генерируем пару ключей
    privateKey, publicKey := generateKeyPair()
    
    // Отправляем только публичный ключ
    sendJSON(w, map[string]interface{}{
        "public_key": publicKey,
        "method": "Diffie-Hellman key exchange",
    })
    
    // Общий ключ вычисляется на стороне клиента и сервера отдельно
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/key/exchange" target="_blank" class="api-endpoint">/api/v1/key/exchange</a></p>
				<form method="GET" action="/challenge/a04/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой ключ вы получили? (первые 6 символов)</label>
						<input type="text" name="key" placeholder="например: abc123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			key := r.URL.Query().Get("key")
			return len(key) >= 3
		},
	}
	
	challenges["a04_9"] = Challenge{
		Title:       "Отсутствие проверки сертификата SSL",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Сложный",
		Description: "Запросы к внешнему API выполняются без проверки SSL сертификата.",
		Task:        "Отправьте запрос к внешнему API без проверки сертификата (симулируйте MITM).",
		Hint:        "💡 Попробуйте запросить /api/v1/external/api?url=https://example.com",
		Explanation: `
			<h3>Проблема</h3>
			<p>Запросы к внешнему API выполняются без проверки SSL сертификата, что позволяет выполнить MITM атаку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ExternalApi(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    
    // УЯЗВИМОСТЬ: Запрос без проверки сертификата
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
        InsecureSkipVerify: true, // ОПАСНО!
    }
    
    resp, _ := http.Get(url)
    // ... остальной код
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код отключает проверку SSL сертификата (InsecureSkipVerify: true), что позволяет злоумышленнику выполнить MITM атаку и перехватить или модифицировать данные.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1ExternalApi(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    
    // ПРОВЕРКА: Всегда проверяем сертификат
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false, // ВСЕГДА false!
            MinVersion:         tls.VersionTLS12,
        },
    }
    
    client := &http.Client{Transport: transport}
    resp, err := client.Get(url)
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/external/api?url=https://example.com" target="_blank" class="api-endpoint">/api/v1/external/api?url=https://example.com</a></p>
				<form method="GET" action="/challenge/a04/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая атака возможна? (напишите: MITM или man-in-the-middle)</label>
						<input type="text" name="attack" placeholder="например: MITM" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			attack := strings.ToLower(r.URL.Query().Get("attack"))
			return strings.Contains(attack, "mitm") || strings.Contains(attack, "man-in-the-middle")
		},
	}
	
	challenges["a04_10"] = Challenge{
		Title:       "Утечка ключей через логи",
		Category:    "A04: Cryptographic Failures",
		Difficulty:  "Средний",
		Description: "API ключи логируются в открытом виде, что позволяет их перехватить.",
		Task:        "Отправьте запрос с API ключом и убедитесь, что он логируется в открытом виде.",
		Hint:        "💡 Попробуйте запросить /api/v1/api/call?api_key=secret123",
		Explanation: `
			<h3>Проблема</h3>
			<p>API ключи логируются в открытом виде, что позволяет злоумышленнику получить их из логов.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1ApiCall(w http.ResponseWriter, r *http.Request) {
    apiKey := r.URL.Query().Get("api_key")
    
    // УЯЗВИМОСТЬ: API ключ логируется в открытом виде
    fmt.Printf("[LOG] API call with key: %s\n", apiKey)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>API ключи логируются в открытом виде без маскирования. При доступе к логам злоумышленник может получить ключи и использовать их для доступа к внешним сервисам.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1ApiCall(w http.ResponseWriter, r *http.Request) {
    apiKey := r.URL.Query().Get("api_key")
    
    // ПРОВЕРКА: Маскируем ключ в логах
    maskedKey := maskAPIKey(apiKey) // Показываем только первые 4 и последние 4 символа
    fmt.Printf("[LOG] API call with key: %s\n", maskedKey)
    
    // Или вообще не логируем ключи
    fmt.Printf("[LOG] API call received\n")
    
    // ... остальной код
}

func maskAPIKey(key string) string {
    if len(key) <= 8 {
        return "****"
    }
    return key[:4] + "****" + key[len(key)-4:]
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/api/call?api_key=secret123" target="_blank" class="api-endpoint">/api/v1/api/call?api_key=secret123</a></p>
				<form method="GET" action="/challenge/a04/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Ключ логируется в открытом виде? (напишите: yes или да)</label>
						<input type="text" name="logged" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			logged := strings.ToLower(r.URL.Query().Get("logged"))
			return logged == "yes" || logged == "да" || logged == "y"
		},
	}
	
	// A05: Остальные задания (4-10)
	challenges["a05_4"] = Challenge{
		Title:       "LDAP Injection",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "LDAP запрос формируется напрямую из пользовательского ввода.",
		Task:        "Выполните LDAP Injection атаку, используя специальные символы (например: admin)(&).",
		Hint:        "💡 Попробуйте запросить /api/v1/ldap/search?username=admin)(&",
		Explanation: `
			<h3>Проблема</h3>
			<p>LDAP запрос формируется напрямую из пользовательского ввода, что позволяет модифицировать запрос через специальные символы.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1LdapSearch(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    
    // УЯЗВИМОСТЬ: LDAP запрос формируется напрямую
    ldapQuery := fmt.Sprintf("(uid=%s)", username)
    
    ldap.Search(ldapQuery)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не экранирует специальные символы LDAP (например, <code>(</code>, <code>)</code>, <code>&</code>, <code>|</code>) перед формированием запроса. Это позволяет злоумышленнику модифицировать запрос и получить доступ к данным других пользователей.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1LdapSearch(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    
    // ПРОВЕРКА: Экранируем специальные символы LDAP
    escapedUsername := ldap.EscapeFilter(username)
    
    // ПРОВЕРКА: Используем параметризованные LDAP запросы
    ldapQuery := fmt.Sprintf("(uid=%s)", escapedUsername)
    
    ldap.Search(ldapQuery)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/ldap/search?username=admin)(&" target="_blank" class="api-endpoint">/api/v1/ldap/search?username=admin)(&</a></p>
				<form method="GET" action="/challenge/a05/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какие специальные символы вы использовали? (например: )( или &)</label>
						<input type="text" name="chars" placeholder="например: )(" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			chars := r.URL.Query().Get("chars")
			return strings.Contains(chars, ")") || strings.Contains(chars, "&") || strings.Contains(chars, "(")
		},
	}
	
	challenges["a05_5"] = Challenge{
		Title:       "NoSQL Injection",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "NoSQL запрос выполняется напрямую без санитизации.",
		Task:        "Выполните NoSQL Injection, используя операторы MongoDB (например: {\"$ne\": null}).",
		Hint:        "💡 Попробуйте запросить /api/v1/users/find?query={\"$ne\": null}",
		Explanation: `
			<h3>Проблема</h3>
			<p>NoSQL запрос выполняется напрямую без санитизации, что позволяет использовать операторы MongoDB для обхода проверок.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersFind(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("query")
    
    // УЯЗВИМОСТЬ: NoSQL запрос выполняется напрямую
    mongoQuery := map[string]interface{}{"username": query}
    
    db.Find(mongoQuery)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не валидирует пользовательский ввод и позволяет использовать операторы MongoDB (например, <code>$ne</code>, <code>$gt</code>, <code>$regex</code>). Это позволяет злоумышленнику обойти проверки и получить доступ к данным.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersFind(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("query")
    
    // ПРОВЕРКА: Валидируем ввод (только строки, без операторов)
    if containsOperator(query) {
        http.Error(w, "Invalid query", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Используем строгий тип для запроса
    mongoQuery := map[string]string{"username": query}
    
    db.Find(mongoQuery)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/find" target="_blank" class="api-endpoint">/api/v1/users/find</a></p>
				<form method="GET" action="/challenge/a05/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой оператор MongoDB вы использовали? (например: $ne)</label>
						<input type="text" name="operator" placeholder="например: $ne" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			op := r.URL.Query().Get("operator")
			return strings.Contains(op, "$ne") || strings.Contains(op, "$gt") || strings.Contains(op, "$")
		},
	}
	
	challenges["a05_6"] = Challenge{
		Title:       "Template Injection",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "Шаблон выполняется без проверки, позволяя выполнить произвольный код.",
		Task:        "Выполните Template Injection атаку через параметр template.",
		Hint:        "💡 Попробуйте запросить /api/v1/render?template={{7*7}}",
		Explanation: `
			<h3>Проблема</h3>
			<p>Шаблон выполняется без проверки, позволяя выполнить произвольный код через синтаксис шаблонизатора.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Render(w http.ResponseWriter, r *http.Request) {
    template := r.URL.Query().Get("template")
    
    // УЯЗВИМОСТЬ: Шаблон выполняется без проверки
    result := executeTemplate(template)
    
    sendJSON(w, map[string]interface{}{"result": result})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не валидирует содержимое шаблона и позволяет использовать синтаксис шаблонизатора (например, <code>{{7*7}}</code> для вычисления или <code>{{config}}</code> для доступа к переменным). Это позволяет выполнить произвольный код.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Render(w http.ResponseWriter, r *http.Request) {
    template := r.URL.Query().Get("template")
    
    // ПРОВЕРКА: Используем whitelist разрешенных шаблонов
    allowedTemplates := []string{"welcome", "error", "success"}
    if !contains(allowedTemplates, template) {
        http.Error(w, "Template not allowed", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Используем безопасный шаблонизатор без выполнения кода
    result := renderSafeTemplate(template)
    
    sendJSON(w, map[string]interface{}{"result": result})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/render" target="_blank" class="api-endpoint">/api/v1/render</a></p>
				<form method="GET" action="/challenge/a05/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Выполнили ли вы Template Injection? (напишите: yes или да)</label>
						<input type="text" name="injected" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			injected := strings.ToLower(r.URL.Query().Get("injected"))
			return injected == "yes" || injected == "да" || injected == "y"
		},
	}
	
	challenges["a05_7"] = Challenge{
		Title:       "XXE в XML парсере",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "XML парсится без отключения внешних сущностей, что позволяет читать файлы.",
		Task:        "Выполните XXE атаку, чтобы прочитать файл /etc/passwd через XML.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/xml/parse с XML содержащим внешнюю сущность",
		Explanation: `
			<h3>Проблема</h3>
			<p>XML парсится без отключения внешних сущностей, что позволяет читать файлы на сервере через XXE атаку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1XmlParse(w http.ResponseWriter, r *http.Request) {
    xmlData := r.FormValue("xml")
    
    // УЯЗВИМОСТЬ: XML парсится без отключения внешних сущностей
    parser := xml.NewDecoder(strings.NewReader(xmlData))
    parser.Decode(&result)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>XML парсер по умолчанию разрешает внешние сущности, что позволяет злоумышленнику создать XML с внешней сущностью, которая будет загружена и включена в результат. Это позволяет читать файлы на сервере.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1XmlParse(w http.ResponseWriter, r *http.Request) {
    xmlData := r.FormValue("xml")
    
    // ПРОВЕРКА: Отключаем внешние сущности
    parser := xml.NewDecoder(strings.NewReader(xmlData))
    parser.Entity = xml.HTMLEntity // Используем только HTML entities
    
    // Или используем безопасный парсер с отключенными внешними сущностями
    // parser := xml.NewDecoder(strings.NewReader(xmlData))
    // parser.Strict = false
    // parser.Entity = xml.HTMLEntity
    
    parser.Decode(&result)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/xml/parse" target="_blank" class="api-endpoint">/api/v1/xml/parse</a></p>
				<form method="GET" action="/challenge/a05/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой тип атаки вы использовали? (напишите: XXE)</label>
						<input type="text" name="attack" placeholder="например: XXE" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			attack := strings.ToUpper(r.URL.Query().Get("attack"))
			return strings.Contains(attack, "XXE")
		},
	}
	
	challenges["a05_8"] = Challenge{
		Title:       "Path Traversal",
		Category:    "A05: Injection",
		Difficulty:  "Средний",
		Description: "Нет проверки пути файла, можно читать любые файлы через ../",
		Task:        "Прочитайте файл /etc/passwd используя Path Traversal (../../../etc/passwd).",
		Hint:        "💡 Попробуйте запросить /api/v1/files/download?file=../../../etc/passwd",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет проверки пути файла, можно читать любые файлы через использование <code>../</code> для выхода из разрешенной директории.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1FilesDownload(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    
    // УЯЗВИМОСТЬ: Нет проверки пути, можно читать любые файлы
    content, _ := ioutil.ReadFile(file)
    w.Write(content)
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет путь файла и не нормализует его. Это позволяет злоумышленнику использовать <code>../</code> для выхода из разрешенной директории и чтения любых файлов на сервере.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1FilesDownload(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    
    // ПРОВЕРКА: Нормализуем путь и проверяем, что он внутри разрешенной директории
    safePath := filepath.Join("/safe/directory", file)
    safePath = filepath.Clean(safePath)
    
    if !strings.HasPrefix(safePath, "/safe/directory") {
        http.Error(w, "Invalid file path", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что файл существует и не является директорией
    if info, err := os.Stat(safePath); err != nil || info.IsDir() {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }
    
    content, _ := ioutil.ReadFile(safePath)
    w.Write(content)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/files/download" target="_blank" class="api-endpoint">/api/v1/files/download</a></p>
				<form method="GET" action="/challenge/a05/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой файл вы прочитали? (например: /etc/passwd)</label>
						<input type="text" name="file" placeholder="например: /etc/passwd" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			file := r.URL.Query().Get("file")
			return strings.Contains(file, "passwd") || strings.Contains(file, "etc") || strings.Contains(file, "../")
		},
	}
	
	challenges["a05_9"] = Challenge{
		Title:       "SSRF в webhook",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "Запрос отправляется к любому URL без проверки, что позволяет выполнить SSRF.",
		Task:        "Выполните SSRF атаку, отправив запрос к localhost:8080/admin или file:///etc/passwd.",
		Hint:        "💡 Попробуйте запросить /api/v1/webhook?url=http://localhost:8080/admin",
		Explanation: `
			<h3>Проблема</h3>
			<p>Запрос отправляется к любому URL без проверки, что позволяет выполнить SSRF атаку и получить доступ к внутренним сервисам.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Webhook(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    
    // УЯЗВИМОСТЬ: Запрос отправляется к любому URL без проверки
    resp, _ := http.Get(url)
    // ... остальной код
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет URL перед отправкой запроса. Это позволяет злоумышленнику отправить запрос к внутренним сервисам (localhost), файловой системе (file://) или другим внутренним ресурсам.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Webhook(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    
    // ПРОВЕРКА: Разрешаем только внешние HTTPS URL
    parsedURL, err := url.Parse(url)
    if err != nil {
        http.Error(w, "Invalid URL", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Запрещаем внутренние адреса
    if isInternalAddress(parsedURL.Host) {
        http.Error(w, "Internal addresses not allowed", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Разрешаем только HTTPS
    if parsedURL.Scheme != "https" {
        http.Error(w, "Only HTTPS allowed", http.StatusForbidden)
        return
    }
    
    resp, _ := http.Get(url)
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/webhook" target="_blank" class="api-endpoint">/api/v1/webhook</a></p>
				<form method="GET" action="/challenge/a05/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой тип атаки вы использовали? (напишите: SSRF)</label>
						<input type="text" name="attack" placeholder="например: SSRF" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			attack := strings.ToUpper(r.URL.Query().Get("attack"))
			return strings.Contains(attack, "SSRF")
		},
	}
	
	challenges["a05_10"] = Challenge{
		Title:       "Code Injection через eval",
		Category:    "A05: Injection",
		Difficulty:  "Сложный",
		Description: "Код выполняется напрямую без проверки (через eval).",
		Task:        "Выполните произвольный код через API (симулируйте Code Injection).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/execute с параметром code",
		Explanation: `
			<h3>Проблема</h3>
			<p>Код выполняется напрямую без проверки (через eval или подобные функции), что позволяет выполнить произвольный код.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Execute(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    
    // УЯЗВИМОСТЬ: Код выполняется напрямую без проверки
    result := eval(code)
    
    sendJSON(w, map[string]interface{}{"result": result})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код использует функции типа <code>eval</code> для выполнения пользовательского ввода. Это позволяет злоумышленнику выполнить произвольный код на сервере.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Execute(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    
    // ПРОВЕРКА: НИКОГДА не выполняем произвольный код
    // Используем whitelist разрешенных операций
    
    // ПРОВЕРКА: Используем sandbox окружение с ограниченными правами
    // ПРОВЕРКА: Используем безопасные языки запросов (например, GraphQL)
    
    http.Error(w, "Code execution not allowed", http.StatusForbidden)
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/execute" target="_blank" class="api-endpoint">/api/v1/execute</a></p>
				<form method="GET" action="/challenge/a05/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Выполнили ли вы Code Injection? (напишите: yes или да)</label>
						<input type="text" name="injected" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			injected := strings.ToLower(r.URL.Query().Get("injected"))
			return injected == "yes" || injected == "да" || injected == "y"
		},
	}
	
	// A06: Остальные задания (3-10)
	challenges["a06_3"] = Challenge{
		Title:       "Отсутствие CAPTCHA",
		Category:    "A06: Insecure Design",
		Difficulty:  "Легкий",
		Description: "Форма контактов не имеет CAPTCHA, что позволяет автоматизировать отправку.",
		Task:        "Отправьте форму контактов без CAPTCHA (симулируйте спам/автоматизацию).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/contact",
		Explanation: `
			<h3>Проблема</h3>
			<p>Форма контактов не имеет CAPTCHA, что позволяет автоматизировать отправку и создавать спам.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1Contact(w http.ResponseWriter, r *http.Request) {
    message := r.FormValue("message")
    
    // УЯЗВИМОСТЬ: Нет CAPTCHA, можно автоматизировать
    sendEmail(message)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не требует прохождения CAPTCHA перед отправкой формы. Это позволяет злоумышленнику автоматизировать отправку форм и создавать спам.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1Contact(w http.ResponseWriter, r *http.Request) {
    message := r.FormValue("message")
    captchaToken := r.FormValue("captcha_token")
    
    // ПРОВЕРКА: Проверяем CAPTCHA
    if !verifyCAPTCHA(captchaToken) {
        http.Error(w, "CAPTCHA verification failed", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Используем rate limiting для форм
    ip := getClientIP(r)
    if !rateLimiter.Allow(ip) {
        http.Error(w, "Too many requests", http.StatusTooManyRequests)
        return
    }
    
    sendEmail(message)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/contact" target="_blank" class="api-endpoint">/api/v1/contact</a></p>
				<form method="GET" action="/challenge/a06/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Есть ли CAPTCHA? (напишите: no или нет)</label>
						<input type="text" name="captcha" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			captcha := strings.ToLower(r.URL.Query().Get("captcha"))
			return captcha == "no" || captcha == "нет" || captcha == "n"
		},
	}
	
	challenges["a06_4"] = Challenge{
		Title:       "Опасные действия через GET",
		Category:    "A06: Insecure Design",
		Difficulty:  "Средний",
		Description: "Удаление пользователя выполняется через GET запрос, что уязвимо для CSRF.",
		Task:        "Удалите пользователя через GET запрос (симулируйте CSRF атаку).",
		Hint:        "💡 Попробуйте запросить /api/v1/users/delete?user_id=123",
		Explanation: `
			<h3>Проблема</h3>
			<p>Удаление пользователя выполняется через GET запрос, что уязвимо для CSRF атак и случайных удалений.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersDeleteGET(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    // УЯЗВИМОСТЬ: Удаление через GET запрос
    deleteUser(userID)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код выполняет опасные действия (удаление) через GET запрос. GET запросы могут быть выполнены автоматически браузером (например, при загрузке изображения), что делает их уязвимыми для CSRF атак.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersDeleteGET(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Опасные действия должны выполняться только через POST/PUT/DELETE
    if r.Method != "POST" && r.Method != "DELETE" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    userID := r.FormValue("user_id")
    
    // ПРОВЕРКА: Проверяем CSRF токен
    if !verifyCSRFToken(r) {
        http.Error(w, "Invalid CSRF token", http.StatusForbidden)
        return
    }
    
    deleteUser(userID)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/delete?user_id=123" target="_blank" class="api-endpoint">/api/v1/users/delete?user_id=123</a></p>
				<form method="GET" action="/challenge/a06/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой метод HTTP вы использовали? (напишите: GET)</label>
						<input type="text" name="method" placeholder="например: GET" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			method := strings.ToUpper(r.URL.Query().Get("method"))
			return method == "GET"
		},
	}
	
	challenges["a06_5"] = Challenge{
		Title:       "Отсутствие проверки бизнес-логики",
		Category:    "A06: Insecure Design",
		Difficulty:  "Средний",
		Description: "Можно перевести отрицательную сумму или больше баланса без проверки.",
		Task:        "Переведите отрицательную сумму (например, -1000) или сумму больше баланса.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/payment/transfer/no-check с amount=-1000",
		Explanation: `
			<h3>Проблема</h3>
			<p>Можно перевести отрицательную сумму или сумму больше баланса без проверки, что нарушает бизнес-логику приложения.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PaymentTransferNoCheck(w http.ResponseWriter, r *http.Request) {
    amount, _ := strconv.Atoi(r.FormValue("amount"))
    
    // УЯЗВИМОСТЬ: Можно перевести отрицательную сумму или больше баланса
    transferMoney(amount)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет бизнес-логику перед выполнением операции. Это позволяет злоумышленнику перевести отрицательную сумму (что может увеличить баланс) или сумму больше баланса (что может создать отрицательный баланс).</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PaymentTransferNoCheck(w http.ResponseWriter, r *http.Request) {
    amount, _ := strconv.Atoi(r.FormValue("amount"))
    
    // ПРОВЕРКА: Сумма должна быть положительной
    if amount <= 0 {
        http.Error(w, "Amount must be positive", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем баланс
    balance := getBalance(userID)
    if amount > balance {
        http.Error(w, "Insufficient funds", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем лимиты перевода
    if amount > maxTransferLimit {
        http.Error(w, "Amount exceeds transfer limit", http.StatusBadRequest)
        return
    }
    
    transferMoney(amount)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/payment/transfer/no-check" target="_blank" class="api-endpoint">/api/v1/payment/transfer/no-check</a></p>
				<form method="GET" action="/challenge/a06/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какую сумму вы перевели? (напишите отрицательное число, например: -1000)</label>
						<input type="number" name="amount" placeholder="например: -1000" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			amount := r.URL.Query().Get("amount")
			return strings.HasPrefix(amount, "-") || amount < "0"
		},
	}
	
	challenges["a06_6"] = Challenge{
		Title:       "Слабые требования к паролю",
		Category:    "A06: Insecure Design",
		Difficulty:  "Легкий",
		Description: "Нет требований к сложности пароля, можно использовать слабые пароли.",
		Task:        "Установите очень слабый пароль (например, 123) без проверки сложности.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/users/password/weak с password=123",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет требований к сложности пароля, можно использовать слабые пароли, которые легко взломать.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersPasswordWeak(w http.ResponseWriter, r *http.Request) {
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет требований к сложности пароля
    setPassword(password)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет сложность пароля перед установкой. Это позволяет пользователям использовать слабые пароли (например, "123" или "password"), которые легко взломать через брутфорс атаку.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersPasswordWeak(w http.ResponseWriter, r *http.Request) {
    password := r.FormValue("password")
    
    // ПРОВЕРКА: Проверяем требования к сложности пароля
    if len(password) < 8 {
        http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
        return
    }
    
    if !hasUpperCase(password) || !hasLowerCase(password) || !hasDigit(password) || !hasSpecialChar(password) {
        http.Error(w, "Password must contain uppercase, lowercase, digit and special character", http.StatusBadRequest)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что пароль не в списке слабых паролей
    if isWeakPassword(password) {
        http.Error(w, "Password is too weak", http.StatusBadRequest)
        return
    }
    
    setPassword(password)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/password/weak" target="_blank" class="api-endpoint">/api/v1/users/password/weak</a></p>
				<form method="GET" action="/challenge/a06/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой слабый пароль вы использовали? (например: 123)</label>
						<input type="text" name="password" placeholder="например: 123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pass := r.URL.Query().Get("password")
			return len(pass) <= 3 || pass == "123" || pass == "abc"
		},
	}
	
	challenges["a06_7"] = Challenge{
		Title:       "Отсутствие 2FA",
		Category:    "A06: Insecure Design",
		Difficulty:  "Средний",
		Description: "Вход выполняется без двухфакторной аутентификации.",
		Task:        "Войдите в систему без 2FA (только один фактор).",
		Hint:        "💡 Попробуйте запросить /api/v1/auth/verify/no-2fa",
		Explanation: `
			<h3>Проблема</h3>
			<p>Вход выполняется без двухфакторной аутентификации, что делает систему уязвимой при компрометации пароля.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthVerifyNo2FA(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет двухфакторной аутентификации
    if checkPassword(email, password) {
        sendJSON(w, map[string]interface{}{"status": "success"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не требует второго фактора аутентификации (например, код из SMS или приложения-аутентификатора). Это делает систему уязвимой при компрометации пароля.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthVerifyNo2FA(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    code := r.FormValue("2fa_code")
    
    // ПРОВЕРКА: Проверяем пароль
    if !checkPassword(email, password) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // ПРОВЕРКА: Требуем второй фактор аутентификации
    if !verify2FACode(email, code) {
        http.Error(w, "Invalid 2FA code", http.StatusUnauthorized)
        return
    }
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/verify/no-2fa" target="_blank" class="api-endpoint">/api/v1/auth/verify/no-2fa</a></p>
				<form method="GET" action="/challenge/a06/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Сколько факторов аутентификации требуется? (напишите число)</label>
						<input type="number" name="factors" placeholder="например: 1" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			factors := r.URL.Query().Get("factors")
			return factors == "1" || factors <= "1"
		},
	}
	
	challenges["a06_8"] = Challenge{
		Title:       "Небезопасный дизайн сессий",
		Category:    "A06: Insecure Design",
		Difficulty:  "Средний",
		Description: "Сессия не истекает и не привязана к IP адресу.",
		Task:        "Создайте сессию и проверьте, что она никогда не истекает.",
		Hint:        "💡 Попробуйте запросить /api/v1/session/create/insecure",
		Explanation: `
			<h3>Проблема</h3>
			<p>Сессия не истекает и не привязана к IP адресу, что делает её уязвимой для перехвата и повторного использования.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1SessionCreateInsecure(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Сессия не истекает и не привязана к IP
    sessionID := generateSessionID()
    
    w.Header().Set("Set-Cookie", fmt.Sprintf("session=%s; Path=/", sessionID))
    sendJSON(w, map[string]interface{}{"session_id": sessionID})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не устанавливает время истечения сессии и не привязывает её к IP адресу. Это позволяет злоумышленнику использовать перехваченную сессию неограниченное время и с любого IP адреса.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1SessionCreateInsecure(w http.ResponseWriter, r *http.Request) {
    sessionID := generateSessionID()
    ip := getClientIP(r)
    
    // ПРОВЕРКА: Устанавливаем время истечения сессии
    expiresAt := time.Now().Add(30 * time.Minute)
    
    // ПРОВЕРКА: Привязываем сессию к IP адресу
    createSession(sessionID, ip, expiresAt)
    
    w.Header().Set("Set-Cookie", fmt.Sprintf("session=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800", sessionID))
    sendJSON(w, map[string]interface{}{"session_id": sessionID, "expires_at": expiresAt})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/session/create/insecure" target="_blank" class="api-endpoint">/api/v1/session/create/insecure</a></p>
				<form method="GET" action="/challenge/a06/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Когда истекает сессия? (напишите: never или никогда)</label>
						<input type="text" name="expires" placeholder="например: never" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			expires := strings.ToLower(r.URL.Query().Get("expires"))
			return expires == "never" || expires == "никогда" || strings.Contains(expires, "never")
		},
	}
	
	challenges["a06_9"] = Challenge{
		Title:       "Отсутствие аудита безопасности",
		Category:    "A06: Insecure Design",
		Difficulty:  "Средний",
		Description: "Критические действия не логируются для аудита безопасности.",
		Task:        "Выполните критическое действие (например, удаление) и убедитесь, что оно не логируется.",
		Hint:        "💡 Попробуйте запросить /api/v1/admin/action?action=delete",
		Explanation: `
			<h3>Проблема</h3>
			<p>Критические действия не логируются для аудита безопасности, что затрудняет расследование инцидентов.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AdminAction(w http.ResponseWriter, r *http.Request) {
    action := r.URL.Query().Get("action")
    
    // УЯЗВИМОСТЬ: Критические действия не логируются
    if action == "delete_all" {
        deleteAllUsers()
    }
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не логирует критические действия (удаление, изменение прав доступа, финансовые операции). Это затрудняет расследование инцидентов и обнаружение несанкционированных действий.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AdminAction(w http.ResponseWriter, r *http.Request) {
    action := r.URL.Query().Get("action")
    user := getCurrentUser(r)
    ip := getClientIP(r)
    
    // ПРОВЕРКА: Логируем все критические действия
    auditLog := AuditLog{
        User:      user.Email,
        Action:    action,
        IP:        ip,
        Timestamp: time.Now(),
        Details:   fmt.Sprintf("Action: %s", action),
    }
    
    logCriticalAction(auditLog)
    
    if action == "delete_all" {
        deleteAllUsers()
    }
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/admin/action?action=delete" target="_blank" class="api-endpoint">/api/v1/admin/action?action=delete</a></p>
				<form method="GET" action="/challenge/a06/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Действие логируется? (напишите: no или нет)</label>
						<input type="text" name="logged" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			logged := strings.ToLower(r.URL.Query().Get("logged"))
			return logged == "no" || logged == "нет" || logged == "n"
		},
	}
	
	challenges["a06_10"] = Challenge{
		Title:       "Небезопасное восстановление пароля",
		Category:    "A06: Insecure Design",
		Difficulty:  "Сложный",
		Description: "Пароль отправляется сразу без проверки владельца email, что позволяет захватить аккаунт.",
		Task:        "Запросите сброс пароля для чужого email без проверки владельца.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/password/reset/insecure с email=victim@example.com",
		Explanation: `
			<h3>Проблема</h3>
			<p>Восстановление пароля не требует подтверждения через email, что позволяет злоумышленнику сбросить пароль любого пользователя.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PasswordResetInsecure(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    newPassword := r.FormValue("new_password")
    
    // УЯЗВИМОСТЬ: Восстановление пароля без подтверждения через email
    resetPassword(email, newPassword)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не требует подтверждения через email перед сбросом пароля. Это позволяет злоумышленнику сбросить пароль любого пользователя, зная только его email.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PasswordResetInsecure(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    token := r.FormValue("token")
    newPassword := r.FormValue("new_password")
    
    // ПРОВЕРКА: Проверяем токен восстановления пароля
    if !verifyPasswordResetToken(email, token) {
        http.Error(w, "Invalid or expired token", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Токен должен быть одноразовым
    if tokenUsed(token) {
        http.Error(w, "Token already used", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Отправляем токен на email, а не позволяем сбросить напрямую
    // sendPasswordResetEmail(email)
    
    resetPassword(email, newPassword)
    markTokenAsUsed(token)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/password/reset/insecure" target="_blank" class="api-endpoint">/api/v1/password/reset/insecure</a></p>
				<form method="GET" action="/challenge/a06/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая атака возможна? (напишите: account takeover или захват аккаунта)</label>
						<input type="text" name="attack" placeholder="например: account takeover" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			attack := strings.ToLower(r.URL.Query().Get("attack"))
			return strings.Contains(attack, "takeover") || strings.Contains(attack, "захват") || strings.Contains(attack, "account")
		},
	}
	
	// A07: Остальные задания (3-10)
	challenges["a07_3"] = Challenge{
		Title:       "Пароли в открытом виде в базе",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Легкий",
		Description: "Пароли хранятся в базе данных в открытом виде без хеширования.",
		Task:        "Получите пароль пользователя из базы данных в открытом виде.",
		Hint:        "💡 Попробуйте запросить /api/v1/users/password/db?user_id=1",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пароли хранятся в базе данных в открытом виде без хеширования, что позволяет получить их напрямую при утечке данных.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UsersPasswordDB(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    // УЯЗВИМОСТЬ: Возвращаем пароли в открытом виде
    password := getPasswordFromDB(userID)
    
    sendJSON(w, map[string]interface{}{"password": password})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Пароли хранятся в базе данных без хеширования. При утечке данных или компрометации базы данных злоумышленник может получить все пароли в открытом виде.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UsersPasswordDB(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    // ПРОВЕРКА: НИКОГДА не возвращаем пароли
    // Пароли должны храниться только в виде хешей (bcrypt, argon2)
    
    // При сохранении пароля:
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    // Сохраняем только hashedPassword в БД
    
    // При проверке пароля:
    err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(inputPassword))
    // ... остальной код
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/users/password/db?user_id=1" target="_blank" class="api-endpoint">/api/v1/users/password/db?user_id=1</a></p>
				<form method="GET" action="/challenge/a07/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пароль вы получили? (например: password123)</label>
						<input type="text" name="password" placeholder="например: password123" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pass := r.URL.Query().Get("password")
			return len(pass) >= 3
		},
	}
	
	challenges["a07_4"] = Challenge{
		Title:       "Слабая проверка сессии",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Средний",
		Description: "Любая строка принимается как валидная сессия без реальной проверки.",
		Task:        "Создайте сессию с произвольным ID без реальной проверки.",
		Hint:        "💡 Попробуйте запросить /api/v1/session/verify?session_id=any_string",
		Explanation: `
			<h3>Проблема</h3>
			<p>Любая строка принимается как валидная сессия без реальной проверки, что позволяет создать произвольную сессию.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1SessionVerify(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    
    // УЯЗВИМОСТЬ: Любая строка принимается как валидная сессия
    if sessionID != "" {
        sendJSON(w, map[string]interface{}{"status": "valid"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет, существует ли сессия в базе данных или хранилище сессий. Это позволяет злоумышленнику создать произвольную сессию и получить доступ к системе.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1SessionVerify(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    
    // ПРОВЕРКА: Проверяем, что сессия существует в хранилище
    session, err := getSession(sessionID)
    if err != nil || session == nil {
        http.Error(w, "Invalid session", http.StatusUnauthorized)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что сессия не истекла
    if session.ExpiresAt.Before(time.Now()) {
        http.Error(w, "Session expired", http.StatusUnauthorized)
        return
    }
    
    sendJSON(w, map[string]interface{}{"status": "valid", "user": session.User})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/session/verify?session_id=any_string" target="_blank" class="api-endpoint">/api/v1/session/verify?session_id=any_string</a></p>
				<form method="GET" action="/challenge/a07/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Вы использовали произвольный session_id? (напишите: yes или да)</label>
						<input type="text" name="arbitrary" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			arb := strings.ToLower(r.URL.Query().Get("arbitrary"))
			return arb == "yes" || arb == "да" || arb == "y"
		},
	}
	
	challenges["a07_5"] = Challenge{
		Title:       "Сессия никогда не истекает",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Средний",
		Description: "Сессия активна навсегда, что позволяет использовать её даже после компрометации.",
		Task:        "Получите информацию о сессии и убедитесь, что она никогда не истекает.",
		Hint:        "💡 Попробуйте запросить /api/v1/session/info",
		Explanation: `
			<h3>Проблема</h3>
			<p>Сессия активна навсегда, что позволяет использовать её даже после компрометации или утечки.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1SessionInfo(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    
    // УЯЗВИМОСТЬ: Сессия никогда не истекает
    sendJSON(w, map[string]interface{}{
        "session_id": sessionID,
        "expires_at": "never",
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не устанавливает время истечения сессии. Это позволяет использовать перехваченную или утечку сессию неограниченное время, даже после того, как пользователь вышел из системы.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1SessionInfo(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    
    session := getSession(sessionID)
    
    // ПРОВЕРКА: Устанавливаем время истечения сессии
    expiresAt := time.Now().Add(30 * time.Minute)
    
    // ПРОВЕРКА: Проверяем, что сессия не истекла
    if session.ExpiresAt.Before(time.Now()) {
        http.Error(w, "Session expired", http.StatusUnauthorized)
        return
    }
    
    sendJSON(w, map[string]interface{}{
        "session_id": sessionID,
        "expires_at": expiresAt,
    })
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/session/info" target="_blank" class="api-endpoint">/api/v1/session/info</a></p>
				<form method="GET" action="/challenge/a07/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Когда истекает сессия? (напишите: never или никогда)</label>
						<input type="text" name="expires" placeholder="например: never" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			expires := strings.ToLower(r.URL.Query().Get("expires"))
			return expires == "never" || expires == "никогда"
		},
	}
	
	challenges["a07_6"] = Challenge{
		Title:       "Небезопасное восстановление пароля",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Сложный",
		Description: "Новый пароль отправляется сразу без проверки владельца email.",
		Task:        "Запросите сброс пароля и получите новый пароль без проверки.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/password/reset/auth с email=user@company.com",
		Explanation: `
			<h3>Проблема</h3>
			<p>Новый пароль отправляется сразу без проверки владельца email, что позволяет злоумышленнику сбросить пароль любого пользователя.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PasswordResetAuth(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    // УЯЗВИМОСТЬ: Новый пароль отправляется сразу без проверки
    newPassword := generatePassword()
    resetPassword(email, newPassword)
    sendEmail(email, newPassword)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не требует подтверждения через email перед сбросом пароля. Это позволяет злоумышленнику сбросить пароль любого пользователя, зная только его email.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PasswordResetAuth(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    // ПРОВЕРКА: Отправляем токен на email, а не новый пароль
    token := generatePasswordResetToken(email)
    sendPasswordResetEmail(email, token)
    
    // ПРОВЕРКА: Пользователь должен перейти по ссылке с токеном
    // Только после проверки токена разрешаем сброс пароля
    
    sendJSON(w, map[string]interface{}{"status": "success", "message": "Password reset link sent to email"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/password/reset/auth" target="_blank" class="api-endpoint">/api/v1/password/reset/auth</a></p>
				<form method="GET" action="/challenge/a07/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Пароль отправляется без проверки? (напишите: yes или да)</label>
						<input type="text" name="no_verify" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			verify := strings.ToLower(r.URL.Query().Get("no_verify"))
			return verify == "yes" || verify == "да" || verify == "y"
		},
	}
	
	challenges["a07_7"] = Challenge{
		Title:       "Отсутствие 2FA",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Средний",
		Description: "Вход выполняется без двухфакторной аутентификации.",
		Task:        "Войдите в систему без 2FA (только email, без кода).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/auth/login/no-2fa с email",
		Explanation: `
			<h3>Проблема</h3>
			<p>Вход выполняется без двухфакторной аутентификации, что делает систему уязвимой при компрометации пароля.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthLoginNo2FA(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет двухфакторной аутентификации
    if checkPassword(email, password) {
        sendJSON(w, map[string]interface{}{"status": "success"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не требует второго фактора аутентификации (например, код из SMS или приложения-аутентификатора). Это делает систему уязвимой при компрометации пароля.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthLoginNo2FA(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    code := r.FormValue("2fa_code")
    
    // ПРОВЕРКА: Проверяем пароль
    if !checkPassword(email, password) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // ПРОВЕРКА: Требуем второй фактор аутентификации
    if !verify2FACode(email, code) {
        http.Error(w, "Invalid 2FA code", http.StatusUnauthorized)
        return
    }
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/login/no-2fa" target="_blank" class="api-endpoint">/api/v1/auth/login/no-2fa</a></p>
				<form method="GET" action="/challenge/a07/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Сколько факторов аутентификации требуется? (напишите число)</label>
						<input type="number" name="factors" placeholder="например: 1" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			factors := r.URL.Query().Get("factors")
			return factors == "1" || factors <= "1"
		},
	}
	
	challenges["a07_8"] = Challenge{
		Title:       "Подделка сессий",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Сложный",
		Description: "Можно подделать сессию, зная формат (например, admin_session_123).",
		Task:        "Создайте админскую сессию, используя предсказуемый формат session_id.",
		Hint:        "💡 Попробуйте запросить /api/v1/session/create/forgery?session_id=admin_session_123",
		Explanation: `
			<h3>Проблема</h3>
			<p>Можно подделать сессию, зная формат (например, admin_session_123), что позволяет создать админскую сессию без авторизации.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1SessionCreateForgery(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    
    // УЯЗВИМОСТЬ: Можно подделать сессию, зная формат
    if strings.HasPrefix(sessionID, "admin_session_") {
        sendJSON(w, map[string]interface{}{"role": "admin"})
    }
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код проверяет только формат session_id, а не его подпись или валидность. Это позволяет злоумышленнику создать админскую сессию, зная формат (например, admin_session_123).</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1SessionCreateForgery(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    
    // ПРОВЕРКА: Проверяем подпись сессии
    if !verifySessionSignature(sessionID) {
        http.Error(w, "Invalid session signature", http.StatusUnauthorized)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что сессия существует в хранилище
    session := getSession(sessionID)
    if session == nil {
        http.Error(w, "Session not found", http.StatusUnauthorized)
        return
    }
    
    // ПРОВЕРКА: Используем криптографически стойкие сессии (JWT с подписью)
    sendJSON(w, map[string]interface{}{"role": session.Role})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/session/create/forgery?session_id=admin_session_123" target="_blank" class="api-endpoint">/api/v1/session/create/forgery?session_id=admin_session_123</a></p>
				<form method="GET" action="/challenge/a07/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какую роль вы получили? (напишите: admin)</label>
						<input type="text" name="role" placeholder="например: admin" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			role := strings.ToLower(r.URL.Query().Get("role"))
			return role == "admin" || strings.Contains(role, "admin")
		},
	}
	
	challenges["a07_9"] = Challenge{
		Title:       "Отсутствие проверки IP адреса",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Средний",
		Description: "Сессия валидна с любого IP адреса, что позволяет перехватить сессию.",
		Task:        "Проверьте сессию и убедитесь, что она работает с любого IP.",
		Hint:        "💡 Попробуйте запросить /api/v1/session/validate",
		Explanation: `
			<h3>Проблема</h3>
			<p>Сессия валидна с любого IP адреса, что позволяет злоумышленнику использовать перехваченную сессию с другого IP.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1SessionValidate(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Сессия валидна с любого IP
    sendJSON(w, map[string]interface{}{
        "status": "valid",
        "ip_check": "disabled",
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет IP адрес, с которого была создана сессия. Это позволяет злоумышленнику использовать перехваченную сессию с другого IP адреса, что делает возможной атаку перехвата сессии (session hijacking).</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1SessionValidate(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session_id")
    currentIP := r.RemoteAddr
    
    session := getSession(sessionID)
    if session == nil {
        http.Error(w, "Invalid session", http.StatusUnauthorized)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что IP адрес совпадает с IP создания сессии
    if session.IPAddress != currentIP {
        http.Error(w, "Session IP mismatch", http.StatusForbidden)
        return
    }
    
    sendJSON(w, map[string]interface{}{"status": "valid"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/session/validate" target="_blank" class="api-endpoint">/api/v1/session/validate</a></p>
				<form method="GET" action="/challenge/a07/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка IP включена? (напишите: no или нет)</label>
						<input type="text" name="ip_check" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			check := strings.ToLower(r.URL.Query().Get("ip_check"))
			return check == "no" || check == "нет" || check == "n" || check == "disabled"
		},
	}
	
	challenges["a07_10"] = Challenge{
		Title:       "Утечка учетных данных в логах",
		Category:    "A07: Authentication Failures",
		Difficulty:  "Средний",
		Description: "Учетные данные логируются в открытом виде, что позволяет их перехватить.",
		Task:        "Войдите в систему и убедитесь, что пароль логируется в открытом виде.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/auth/login/log с email и password",
		Explanation: `
			<h3>Проблема</h3>
			<p>Учетные данные (пароли) логируются в открытом виде, что позволяет злоумышленнику получить их при доступе к логам.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthLoginLog(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Учетные данные логируются в открытом виде
    fmt.Printf("[LOG] Login attempt - email: %s, password: %s\\n", email, password)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код логирует пароль в открытом виде. При доступе к логам (например, через утечку или компрометацию сервера) злоумышленник может получить все пароли пользователей.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthLoginLog(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // ПРОВЕРКА: НИКОГДА не логируем пароли
    // Логируем только email и результат попытки входа
    fmt.Printf("[LOG] Login attempt - email: %s, result: %s\\n", email, "success/error")
    
    // ПРОВЕРКА: Если нужно логировать попытки входа, используем только email и IP
    fmt.Printf("[LOG] Login attempt - email: %s, IP: %s, timestamp: %s\\n", 
        email, r.RemoteAddr, time.Now())
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/login/log" target="_blank" class="api-endpoint">/api/v1/auth/login/log</a></p>
				<form method="GET" action="/challenge/a07/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Пароль логируется в открытом виде? (напишите: yes или да)</label>
						<input type="text" name="logged" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			logged := strings.ToLower(r.URL.Query().Get("logged"))
			return logged == "yes" || logged == "да" || logged == "y"
		},
	}
	
	// A08: Все задания (1-10)
	challenges["a08_1"] = Challenge{
		Title:       "Загрузка файлов без проверки подписи",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Средний",
		Description: "Файлы загружаются без проверки цифровой подписи, что позволяет загрузить вредоносный код.",
		Task:        "Загрузите файл обновления без проверки подписи.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/update/upload с параметром file",
		Explanation: `
			<h3>Проблема</h3>
			<p>Файлы загружаются без проверки цифровой подписи, что позволяет злоумышленнику загрузить вредоносный код.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UpdateUpload(w http.ResponseWriter, r *http.Request) {
    file := r.FormValue("file")
    
    // УЯЗВИМОСТЬ: Файл загружается без проверки цифровой подписи
    uploadFile(file)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет цифровую подпись файла перед загрузкой. Это позволяет злоумышленнику загрузить вредоносный код, который может быть выполнен на сервере.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UpdateUpload(w http.ResponseWriter, r *http.Request) {
    file := r.FormValue("file")
    signature := r.FormValue("signature")
    
    // ПРОВЕРКА: Проверяем цифровую подпись файла
    if !verifyFileSignature(file, signature) {
        http.Error(w, "Invalid file signature", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что подпись принадлежит доверенному разработчику
    if !verifyDeveloperSignature(signature) {
        http.Error(w, "Untrusted developer", http.StatusForbidden)
        return
    }
    
    uploadFile(file)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/update/upload" target="_blank" class="api-endpoint">/api/v1/update/upload</a></p>
				<form method="GET" action="/challenge/a08/1">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой файл вы загрузили? (например: update.zip)</label>
						<input type="text" name="file" placeholder="например: update.zip" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			file := r.URL.Query().Get("file")
			return len(file) > 0
		},
	}
	
	challenges["a08_2"] = Challenge{
		Title:       "Обновление без проверки подписи",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Средний",
		Description: "Обновление выполняется без проверки подписи разработчика.",
		Task:        "Обновите приложение до версии 2.0.0 без проверки подписи.",
		Hint:        "💡 Попробуйте запросить /api/v1/update/install?version=2.0.0",
		Explanation: `
			<h3>Проблема</h3>
			<p>Обновление выполняется без проверки подписи разработчика, что позволяет установить скомпрометированное обновление.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1UpdateInstall(w http.ResponseWriter, r *http.Request) {
    version := r.URL.Query().Get("version")
    
    // УЯЗВИМОСТЬ: Обновление выполняется без проверки подписи разработчика
    installUpdate(version)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет цифровую подпись разработчика перед установкой обновления. Это позволяет злоумышленнику установить скомпрометированное обновление, которое может содержать вредоносный код.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1UpdateInstall(w http.ResponseWriter, r *http.Request) {
    version := r.URL.Query().Get("version")
    signature := r.URL.Query().Get("signature")
    
    // ПРОВЕРКА: Проверяем подпись разработчика
    if !verifyDeveloperSignature(version, signature) {
        http.Error(w, "Invalid developer signature", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что версия существует в доверенном репозитории
    if !isVersionTrusted(version) {
        http.Error(w, "Untrusted version", http.StatusForbidden)
        return
    }
    
    installUpdate(version)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/update/install?version=2.0.0" target="_blank" class="api-endpoint">/api/v1/update/install?version=2.0.0</a></p>
				<form method="GET" action="/challenge/a08/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>До какой версии вы обновили? (например: 2.0.0)</label>
						<input type="text" name="version" placeholder="например: 2.0.0" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			version := r.URL.Query().Get("version")
			return len(version) > 0
		},
	}
	
	challenges["a08_3"] = Challenge{
		Title:       "Данные без проверки целостности",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Средний",
		Description: "Данные сохраняются без checksum, что позволяет их изменить без обнаружения.",
		Task:        "Сохраните данные без проверки целостности (checksum).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/data/save с параметром data",
		Explanation: `
			<h3>Проблема</h3>
			<p>Данные сохраняются без проверки целостности (checksum), что позволяет изменить их без обнаружения.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1DataSave(w http.ResponseWriter, r *http.Request) {
    data := r.FormValue("data")
    
    // УЯЗВИМОСТЬ: Данные сохраняются без checksum
    saveData(data)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не вычисляет и не проверяет checksum (контрольную сумму) данных перед сохранением. Это позволяет злоумышленнику изменить данные без обнаружения.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1DataSave(w http.ResponseWriter, r *http.Request) {
    data := r.FormValue("data")
    checksum := r.FormValue("checksum")
    
    // ПРОВЕРКА: Вычисляем checksum данных
    calculatedChecksum := calculateSHA256(data)
    
    // ПРОВЕРКА: Проверяем, что checksum совпадает
    if calculatedChecksum != checksum {
        http.Error(w, "Data integrity check failed", http.StatusForbidden)
        return
    }
    
    saveData(data, checksum)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/data/save" target="_blank" class="api-endpoint">/api/v1/data/save</a></p>
				<form method="GET" action="/challenge/a08/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка целостности выполняется? (напишите: no или нет)</label>
						<input type="text" name="checksum" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			checksum := strings.ToLower(r.URL.Query().Get("checksum"))
			return checksum == "no" || checksum == "нет" || checksum == "n"
		},
	}
	
	challenges["a08_4"] = Challenge{
		Title:       "Загрузка зависимостей без проверки",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Средний",
		Description: "Пакеты устанавливаются без проверки подписи.",
		Task:        "Установите пакет без проверки подписи.",
		Hint:        "💡 Попробуйте запросить /api/v1/dependencies/install?package=malicious-package",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пакеты устанавливаются без проверки подписи, что позволяет установить скомпрометированный пакет.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1DependenciesInstall(w http.ResponseWriter, r *http.Request) {
    packageName := r.URL.Query().Get("package")
    
    // УЯЗВИМОСТЬ: Пакет устанавливается без проверки подписи
    installPackage(packageName)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет цифровую подпись пакета перед установкой. Это позволяет злоумышленнику установить скомпрометированный пакет, который может содержать вредоносный код.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1DependenciesInstall(w http.ResponseWriter, r *http.Request) {
    packageName := r.URL.Query().Get("package")
    signature := r.URL.Query().Get("signature")
    
    // ПРОВЕРКА: Проверяем подпись пакета
    if !verifyPackageSignature(packageName, signature) {
        http.Error(w, "Invalid package signature", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что пакет из доверенного репозитория
    if !isPackageFromTrustedRepo(packageName) {
        http.Error(w, "Untrusted package source", http.StatusForbidden)
        return
    }
    
    installPackage(packageName)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/dependencies/install?package=malicious-package" target="_blank" class="api-endpoint">/api/v1/dependencies/install?package=malicious-package</a></p>
				<form method="GET" action="/challenge/a08/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой пакет вы установили? (например: malicious-package)</label>
						<input type="text" name="package" placeholder="например: malicious-package" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			pkg := r.URL.Query().Get("package")
			return len(pkg) > 0
		},
	}
	
	challenges["a08_5"] = Challenge{
		Title:       "Файлы без проверки checksum",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Средний",
		Description: "Файлы загружаются без проверки SHA256/MD5 checksum.",
		Task:        "Загрузите файл без проверки целостности (checksum).",
		Hint:        "💡 Отправьте POST запрос на /api/v1/files/upload с параметром file",
		Explanation: `
			<h3>Проблема</h3>
			<p>Файлы загружаются без проверки checksum (SHA256/MD5), что позволяет загрузить измененный файл.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1FilesUpload(w http.ResponseWriter, r *http.Request) {
    file := r.FormValue("file")
    
    // УЯЗВИМОСТЬ: Файл загружается без проверки SHA256/MD5
    uploadFile(file)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет checksum файла перед загрузкой. Это позволяет злоумышленнику загрузить измененный файл без обнаружения.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1FilesUpload(w http.ResponseWriter, r *http.Request) {
    file := r.FormValue("file")
    expectedChecksum := r.FormValue("checksum")
    
    // ПРОВЕРКА: Вычисляем checksum загруженного файла
    actualChecksum := calculateSHA256(file)
    
    // ПРОВЕРКА: Проверяем, что checksum совпадает
    if actualChecksum != expectedChecksum {
        http.Error(w, "File integrity check failed", http.StatusForbidden)
        return
    }
    
    uploadFile(file)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/files/upload" target="_blank" class="api-endpoint">/api/v1/files/upload</a></p>
				<form method="GET" action="/challenge/a08/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка checksum выполняется? (напишите: no или нет)</label>
						<input type="text" name="checksum" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			checksum := strings.ToLower(r.URL.Query().Get("checksum"))
			return checksum == "no" || checksum == "нет" || checksum == "n"
		},
	}
	
	challenges["a08_6"] = Challenge{
		Title:       "CI/CD без проверки подписи",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Сложный",
		Description: "CI/CD pipeline не проверяет подпись кода перед деплоем.",
		Task:        "Задеплойте код через CI/CD без проверки подписи.",
		Hint:        "💡 Попробуйте запросить /api/v1/cicd/deploy",
		Explanation: `
			<h3>Проблема</h3>
			<p>CI/CD pipeline не проверяет подпись кода перед развертыванием, что позволяет развернуть скомпрометированный код.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1CICDDeploy(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: CI/CD pipeline не проверяет подпись кода
    deployCode()
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>CI/CD pipeline не проверяет цифровую подпись кода перед развертыванием. Это позволяет злоумышленнику развернуть скомпрометированный код через компрометацию CI/CD системы.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1CICDDeploy(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    signature := r.FormValue("signature")
    
    // ПРОВЕРКА: Проверяем подпись кода
    if !verifyCodeSignature(code, signature) {
        http.Error(w, "Invalid code signature", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что код подписан доверенным разработчиком
    if !verifyDeveloperSignature(signature) {
        http.Error(w, "Untrusted developer", http.StatusForbidden)
        return
    }
    
    deployCode(code)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/cicd/deploy" target="_blank" class="api-endpoint">/api/v1/cicd/deploy</a></p>
				<form method="GET" action="/challenge/a08/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка подписи выполняется? (напишите: no или нет)</label>
						<input type="text" name="signature" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sig := strings.ToLower(r.URL.Query().Get("signature"))
			return sig == "no" || sig == "нет" || sig == "n"
		},
	}
	
	challenges["a08_7"] = Challenge{
		Title:       "Репозиторий без проверки подписи коммитов",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Сложный",
		Description: "Репозиторий клонируется без проверки подписи коммитов.",
		Task:        "Клонируйте репозиторий без проверки подписи коммитов.",
		Hint:        "💡 Попробуйте запросить /api/v1/repo/pull?repo=https://github.com/evil/repo",
		Explanation: `
			<h3>Проблема</h3>
			<p>Репозиторий клонируется без проверки подписи коммитов, что позволяет выполнить скомпрометированные коммиты.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1RepoPull(w http.ResponseWriter, r *http.Request) {
    repo := r.URL.Query().Get("repo")
    
    // УЯЗВИМОСТЬ: Репозиторий клонируется без проверки подписи
    pullRepository(repo)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет GPG подпись коммитов перед клонированием репозитория. Это позволяет злоумышленнику выполнить скомпрометированные коммиты.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1RepoPull(w http.ResponseWriter, r *http.Request) {
    repo := r.URL.Query().Get("repo")
    
    // ПРОВЕРКА: Проверяем GPG подпись всех коммитов
    if !verifyCommitSignatures(repo) {
        http.Error(w, "Invalid commit signatures", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что коммиты подписаны доверенными разработчиками
    if !verifyTrustedCommitters(repo) {
        http.Error(w, "Untrusted committers", http.StatusForbidden)
        return
    }
    
    pullRepository(repo)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/repo/pull" target="_blank" class="api-endpoint">/api/v1/repo/pull</a></p>
				<form method="GET" action="/challenge/a08/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка подписи коммитов выполняется? (напишите: no или нет)</label>
						<input type="text" name="signature" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sig := strings.ToLower(r.URL.Query().Get("signature"))
			return sig == "no" || sig == "нет" || sig == "n"
		},
	}
	
	challenges["a08_8"] = Challenge{
		Title:       "Код выполняется без проверки подписи",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Сложный",
		Description: "Код выполняется без проверки цифровой подписи.",
		Task:        "Выполните код без проверки подписи.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/code/execute с параметром code",
		Explanation: `
			<h3>Проблема</h3>
			<p>Код выполняется без проверки цифровой подписи, что позволяет выполнить вредоносный код.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1CodeExecute(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    
    // УЯЗВИМОСТЬ: Код выполняется без проверки цифровой подписи
    executeCode(code)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет цифровую подпись перед выполнением. Это позволяет злоумышленнику выполнить вредоносный код.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1CodeExecute(w http.ResponseWriter, r *http.Request) {
    code := r.FormValue("code")
    signature := r.FormValue("signature")
    
    // ПРОВЕРКА: Проверяем цифровую подпись кода
    if !verifyCodeSignature(code, signature) {
        http.Error(w, "Invalid code signature", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что код подписан доверенным разработчиком
    if !verifyDeveloperSignature(signature) {
        http.Error(w, "Untrusted developer", http.StatusForbidden)
        return
    }
    
    executeCode(code)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/code/execute" target="_blank" class="api-endpoint">/api/v1/code/execute</a></p>
				<form method="GET" action="/challenge/a08/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка подписи выполняется? (напишите: no или нет)</label>
						<input type="text" name="signature" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sig := strings.ToLower(r.URL.Query().Get("signature"))
			return sig == "no" || sig == "нет" || sig == "n"
		},
	}
	
	challenges["a08_9"] = Challenge{
		Title:       "Цепочка доверия не проверяется",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Сложный",
		Description: "Сертификаты не проверяются, что позволяет принять поддельные сертификаты.",
		Task:        "Проверьте сертификат и убедитесь, что цепочка доверия не проверяется.",
		Hint:        "💡 Попробуйте запросить /api/v1/certificate/verify",
		Explanation: `
			<h3>Проблема</h3>
			<p>Сертификаты не проверяются, что позволяет принять поддельные сертификаты.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1CertificateVerify(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Сертификаты не проверяются
    acceptCertificate()
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет цепочку доверия сертификатов. Это позволяет злоумышленнику использовать поддельные сертификаты для MITM атак.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1CertificateVerify(w http.ResponseWriter, r *http.Request) {
    certificate := r.FormValue("certificate")
    
    // ПРОВЕРКА: Проверяем цепочку доверия сертификата
    if !verifyCertificateChain(certificate) {
        http.Error(w, "Invalid certificate chain", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что сертификат выдан доверенным центром сертификации
    if !verifyTrustedCA(certificate) {
        http.Error(w, "Untrusted certificate authority", http.StatusForbidden)
        return
    }
    
    acceptCertificate(certificate)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/certificate/verify" target="_blank" class="api-endpoint">/api/v1/certificate/verify</a></p>
				<form method="GET" action="/challenge/a08/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Цепочка доверия проверяется? (напишите: no или нет)</label>
						<input type="text" name="chain" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			chain := strings.ToLower(r.URL.Query().Get("chain"))
			return chain == "no" || chain == "нет" || chain == "n"
		},
	}
	
	challenges["a08_10"] = Challenge{
		Title:       "Нет проверки времени модификации",
		Category:    "A08: Software or Data Integrity Failures",
		Difficulty:  "Средний",
		Description: "Нет проверки времени модификации файла, что позволяет откатить файл к предыдущей версии.",
		Task:        "Проверьте файл и убедитесь, что время модификации не проверяется.",
		Hint:        "💡 Попробуйте запросить /api/v1/file/check?file=config.json",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет проверки времени модификации файла, что позволяет откатить файл к предыдущей версии.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1FileCheck(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    
    // УЯЗВИМОСТЬ: Нет проверки времени модификации файла
    checkFile(file)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не проверяет время модификации файла. Это позволяет злоумышленнику откатить файл к предыдущей версии без обнаружения.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1FileCheck(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    expectedTimestamp := r.URL.Query().Get("timestamp")
    
    // ПРОВЕРКА: Получаем время модификации файла
    actualTimestamp := getFileModificationTime(file)
    
    // ПРОВЕРКА: Проверяем, что время модификации совпадает
    if actualTimestamp != expectedTimestamp {
        http.Error(w, "File timestamp mismatch", http.StatusForbidden)
        return
    }
    
    // ПРОВЕРКА: Проверяем, что файл не был откачен к предыдущей версии
    if isFileRolledBack(file, expectedTimestamp) {
        http.Error(w, "File rolled back", http.StatusForbidden)
        return
    }
    
    checkFile(file)
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/file/check?file=config.json" target="_blank" class="api-endpoint">/api/v1/file/check?file=config.json</a></p>
				<form method="GET" action="/challenge/a08/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка времени модификации выполняется? (напишите: no или нет)</label>
						<input type="text" name="timestamp" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			ts := strings.ToLower(r.URL.Query().Get("timestamp"))
			return ts == "no" || ts == "нет" || ts == "n"
		},
	}
	
	// A09: Остальные задания (2-10)
	challenges["a09_2"] = Challenge{
		Title:       "Чувствительные данные в логах",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Пароли логируются в открытом виде, что позволяет их перехватить.",
		Task:        "Войдите в систему и убедитесь, что пароль логируется в открытом виде.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/auth/login/log-sensitive с email и password",
		Explanation: `
			<h3>Проблема</h3>
			<p>Пароли логируются в открытом виде, что позволяет злоумышленнику получить их при доступе к логам.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthLoginLogSensitive(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Пароль логируется в открытом виде
    fmt.Printf("[LOG] Login attempt - email: %s, password: %s\\n", email, password)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код логирует пароль в открытом виде. При доступе к логам (например, через утечку или компрометацию сервера) злоумышленник может получить все пароли пользователей.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthLoginLogSensitive(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // ПРОВЕРКА: НИКОГДА не логируем пароли
    // Логируем только email и результат попытки входа
    fmt.Printf("[LOG] Login attempt - email: %s, result: %s\\n", email, "success/error")
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/login/log-sensitive" target="_blank" class="api-endpoint">/api/v1/auth/login/log-sensitive</a></p>
				<form method="GET" action="/challenge/a09/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Пароль логируется в открытом виде? (напишите: yes или да)</label>
						<input type="text" name="logged" placeholder="например: yes" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			logged := strings.ToLower(r.URL.Query().Get("logged"))
			return logged == "yes" || logged == "да" || logged == "y"
		},
	}
	
	challenges["a09_3"] = Challenge{
		Title:       "Мониторинг не настроен",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Легкий",
		Description: "Нет мониторинга подозрительной активности.",
		Task:        "Проверьте статус системы и убедитесь, что мониторинг отключен.",
		Hint:        "💡 Попробуйте запросить /api/v1/system/status",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет мониторинга подозрительной активности, что не позволяет обнаружить атаки в реальном времени.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1SystemStatus(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Нет мониторинга подозрительной активности
    sendJSON(w, map[string]interface{}{
        "status": "operational",
        "monitoring": "disabled",
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не настроен для мониторинга подозрительной активности. Это не позволяет обнаружить атаки в реальном времени и быстро реагировать на инциденты.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1SystemStatus(w http.ResponseWriter, r *http.Request) {
    // ПРОВЕРКА: Включаем мониторинг подозрительной активности
    enableSecurityMonitoring()
    
    // ПРОВЕРКА: Настраиваем алерты для критических событий
    configureAlerts([]string{
        "multiple_failed_logins",
        "unusual_api_access",
        "data_exfiltration",
    })
    
    sendJSON(w, map[string]interface{}{
        "status": "operational",
        "monitoring": "enabled",
    })
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/system/status" target="_blank" class="api-endpoint">/api/v1/system/status</a></p>
				<form method="GET" action="/challenge/a09/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Мониторинг включен? (напишите: no или нет)</label>
						<input type="text" name="monitoring" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			mon := strings.ToLower(r.URL.Query().Get("monitoring"))
			return mon == "no" || mon == "нет" || mon == "n" || mon == "disabled"
		},
	}
	
	challenges["a09_4"] = Challenge{
		Title:       "Недостаточное логирование",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Логируется только сумма платежа, без IP, времени, пользователя и ID транзакции.",
		Task:        "Обработайте платеж и убедитесь, что логируется недостаточно информации.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/payment/process/insufficient-log с amount",
		Explanation: `
			<h3>Проблема</h3>
			<p>Логируется только сумма платежа, без IP, времени, пользователя и ID транзакции, что не позволяет отследить подозрительную активность.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1PaymentProcessInsufficientLog(w http.ResponseWriter, r *http.Request) {
    amount := r.FormValue("amount")
    
    // УЯЗВИМОСТЬ: Логируется только сумма, без IP, времени, пользователя
    fmt.Printf("[LOG] Payment: %s\\n", amount)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код логирует только минимальную информацию (сумму платежа), без IP адреса, времени, ID пользователя и ID транзакции. Это не позволяет отследить подозрительную активность и расследовать инциденты.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1PaymentProcessInsufficientLog(w http.ResponseWriter, r *http.Request) {
    amount := r.FormValue("amount")
    userID := getUserID(r)
    transactionID := generateTransactionID()
    
    // ПРОВЕРКА: Логируем всю необходимую информацию
    fmt.Printf("[LOG] Payment - amount: %s, user_id: %s, transaction_id: %s, IP: %s, timestamp: %s\\n", 
        amount, userID, transactionID, r.RemoteAddr, time.Now())
    
    sendJSON(w, map[string]interface{}{"status": "success", "transaction_id": transactionID})
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/payment/process/insufficient-log" target="_blank" class="api-endpoint">/api/v1/payment/process/insufficient-log</a></p>
				<form method="GET" action="/challenge/a09/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая информация отсутствует в логах? (напишите: IP или timestamp или user_id)</label>
						<input type="text" name="missing" placeholder="например: IP" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			missing := strings.ToLower(r.URL.Query().Get("missing"))
			return strings.Contains(missing, "ip") || strings.Contains(missing, "timestamp") || strings.Contains(missing, "user") || strings.Contains(missing, "transaction")
		},
	}
	
	challenges["a09_5"] = Challenge{
		Title:       "Отсутствие алертов",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Нет алерта при множественных неудачных попытках входа (брутфорс).",
		Task:        "Попробуйте войти несколько раз с неправильным паролем и убедитесь, что алерт не отправляется.",
		Hint:        "💡 Попробуйте запросить /api/v1/auth/failed/login",
		Explanation: `
			<h3>Проблема</h3>
			<p>Нет алерта при множественных неудачных попытках входа (брутфорс), что не позволяет быстро обнаружить атаку.</p>
			
			<h3>Уязвимый код</h3>
			<pre class="response"><code>func apiV1AuthFailedLogin(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: Нет алерта при множественных неудачных попытках
    sendJSON(w, map[string]interface{}{
        "status": "error",
        "message": "Login failed (no alert sent!)",
    })
}</code></pre>
			
			<h3>Почему это происходит</h3>
			<p>Код не отправляет алерт при множественных неудачных попытках входа. Это не позволяет быстро обнаружить брутфорс атаку и принять меры по защите.</p>
			
			<h3>Как исправить</h3>
			<pre class="response"><code>func apiV1AuthFailedLogin(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    // ПРОВЕРКА: Отслеживаем количество неудачных попыток
    failedAttempts := incrementFailedAttempts(email)
    
    // ПРОВЕРКА: Отправляем алерт при множественных неудачных попытках
    if failedAttempts >= 5 {
        sendSecurityAlert("Multiple failed login attempts", map[string]interface{}{
            "email": email,
            "attempts": failedAttempts,
            "IP": r.RemoteAddr,
        })
    }
    
    sendJSON(w, map[string]interface{}{
        "status": "error",
        "message": "Login failed",
    })
}</code></pre>
		`,
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/auth/failed/login" target="_blank" class="api-endpoint">/api/v1/auth/failed/login</a></p>
				<form method="GET" action="/challenge/a09/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Алерт отправляется? (напишите: no или нет)</label>
						<input type="text" name="alert" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			alert := strings.ToLower(r.URL.Query().Get("alert"))
			return alert == "no" || alert == "нет" || alert == "n"
		},
	}
	
	challenges["a09_6"] = Challenge{
		Title:       "Логи в открытом доступе",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Логи доступны без аутентификации, раскрывая чувствительную информацию.",
		Task:        "Получите доступ к логам и найдите JWT токен или пароль в них.",
		Hint:        "💡 Попробуйте запросить /api/v1/logs/access",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/logs/access" target="_blank" class="api-endpoint">/api/v1/logs/access</a></p>
				<form method="GET" action="/challenge/a09/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая чувствительная информация была в логах? (напишите: JWT или password или token)</label>
						<input type="text" name="sensitive" placeholder="например: JWT" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sensitive := strings.ToLower(r.URL.Query().Get("sensitive"))
			return strings.Contains(sensitive, "jwt") || strings.Contains(sensitive, "password") || strings.Contains(sensitive, "token")
		},
	}
	
	challenges["a09_7"] = Challenge{
		Title:       "Отсутствие корреляции событий",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Сложный",
		Description: "События не коррелируются, что не позволяет обнаружить паттерны атак.",
		Task:        "Получите список событий и убедитесь, что корреляция не выполняется.",
		Hint:        "💡 Попробуйте запросить /api/v1/events/list",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/events/list" target="_blank" class="api-endpoint">/api/v1/events/list</a></p>
				<form method="GET" action="/challenge/a09/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Корреляция событий выполняется? (напишите: no или нет)</label>
						<input type="text" name="correlation" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			corr := strings.ToLower(r.URL.Query().Get("correlation"))
			return corr == "no" || corr == "нет" || corr == "n"
		},
	}
	
	challenges["a09_8"] = Challenge{
		Title:       "Недостаточная детализация логов",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Логируется только действие, без деталей (пользователь, IP, время, параметры, результат).",
		Task:        "Выполните действие и убедитесь, что в логах недостаточно деталей.",
		Hint:        "💡 Попробуйте запросить /api/v1/action/execute?action=delete",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/action/execute?action=delete" target="_blank" class="api-endpoint">/api/v1/action/execute?action=delete</a></p>
				<form method="GET" action="/challenge/a09/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая информация отсутствует в логах? (напишите: user или IP или timestamp)</label>
						<input type="text" name="missing" placeholder="например: user" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			missing := strings.ToLower(r.URL.Query().Get("missing"))
			return strings.Contains(missing, "user") || strings.Contains(missing, "ip") || strings.Contains(missing, "timestamp") || strings.Contains(missing, "parameters")
		},
	}
	
	challenges["a09_9"] = Challenge{
		Title:       "Анализ логов не выполняется",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Логи не анализируются автоматически, что не позволяет обнаружить подозрительную активность.",
		Task:        "Проверьте анализ логов и убедитесь, что он отключен.",
		Hint:        "💡 Попробуйте запросить /api/v1/logs/analyze",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/logs/analyze" target="_blank" class="api-endpoint">/api/v1/logs/analyze</a></p>
				<form method="GET" action="/challenge/a09/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Анализ логов включен? (напишите: no или нет)</label>
						<input type="text" name="analysis" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			analysis := strings.ToLower(r.URL.Query().Get("analysis"))
			return analysis == "no" || analysis == "нет" || analysis == "n" || analysis == "disabled"
		},
	}
	
	challenges["a09_10"] = Challenge{
		Title:       "Логи хранятся небезопасно",
		Category:    "A09: Security Logging and Alerting Failures",
		Difficulty:  "Средний",
		Description: "Логи хранятся в открытом виде без шифрования.",
		Task:        "Проверьте хранилище логов и убедитесь, что они не зашифрованы.",
		Hint:        "💡 Попробуйте запросить /api/v1/logs/storage",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/logs/storage" target="_blank" class="api-endpoint">/api/v1/logs/storage</a></p>
				<form method="GET" action="/challenge/a09/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Логи зашифрованы? (напишите: no или нет)</label>
						<input type="text" name="encrypted" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			enc := strings.ToLower(r.URL.Query().Get("encrypted"))
			return enc == "no" || enc == "нет" || enc == "n" || enc == "unencrypted"
		},
	}
	
	// A10: Остальные задания (2-10)
	challenges["a10_2"] = Challenge{
		Title:       "Отсутствие обработки ошибок",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "Нет проверки на ошибку парсинга, что может вызвать панику (деление на ноль).",
		Task:        "Выполните деление на ноль и убедитесь, что ошибка не обрабатывается.",
		Hint:        "💡 Попробуйте запросить /api/v1/calculate?number=0",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/calculate?number=0" target="_blank" class="api-endpoint">/api/v1/calculate?number=0</a></p>
				<form method="GET" action="/challenge/a10/2">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая ошибка может произойти? (напишите: division by zero или деление на ноль)</label>
						<input type="text" name="error" placeholder="например: division by zero" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			err := strings.ToLower(r.URL.Query().Get("error"))
			return strings.Contains(err, "division") || strings.Contains(err, "zero") || strings.Contains(err, "деление") || strings.Contains(err, "ноль")
		},
	}
	
	challenges["a10_3"] = Challenge{
		Title:       "Чувствительные данные в логах ошибок",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "Полная информация об ошибке с чувствительными данными логируется.",
		Task:        "Выполните запрос к базе данных и убедитесь, что пароль логируется в ошибке.",
		Hint:        "💡 Попробуйте запросить /api/v1/database/query?query=SELECT",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/database/query?query=SELECT" target="_blank" class="api-endpoint">/api/v1/database/query?query=SELECT</a></p>
				<form method="GET" action="/challenge/a10/3">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая чувствительная информация логируется? (напишите: password или пароль)</label>
						<input type="text" name="sensitive" placeholder="например: password" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			sensitive := strings.ToLower(r.URL.Query().Get("sensitive"))
			return strings.Contains(sensitive, "password") || strings.Contains(sensitive, "пароль") || strings.Contains(sensitive, "database")
		},
	}
	
	challenges["a10_4"] = Challenge{
		Title:       "Stack trace в ответе",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "Полный stack trace показывается пользователю, раскрывая структуру кода.",
		Task:        "Вызовите ошибку и получите полный stack trace в ответе.",
		Hint:        "💡 Попробуйте запросить /api/v1/process",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/process" target="_blank" class="api-endpoint">/api/v1/process</a></p>
				<form method="GET" action="/challenge/a10/4">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Что было раскрыто? (напишите: stack trace или стек вызовов)</label>
						<input type="text" name="exposed" placeholder="например: stack trace" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			exposed := strings.ToLower(r.URL.Query().Get("exposed"))
			return strings.Contains(exposed, "stack") || strings.Contains(exposed, "trace") || strings.Contains(exposed, "стек")
		},
	}
	
	challenges["a10_5"] = Challenge{
		Title:       "Отсутствие валидации входных данных",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "Нет проверки на отрицательные значения, что позволяет перевести отрицательную сумму.",
		Task:        "Переведите отрицательную сумму (например, -1000) без валидации.",
		Hint:        "💡 Отправьте POST запрос на /api/v1/transfer с amount=-1000",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/transfer" target="_blank" class="api-endpoint">/api/v1/transfer</a></p>
				<form method="GET" action="/challenge/a10/5">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какую отрицательную сумму вы перевели? (например: -1000)</label>
						<input type="number" name="amount" placeholder="например: -1000" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			amount := r.URL.Query().Get("amount")
			return strings.HasPrefix(amount, "-") || amount < "0"
		},
	}
	
	challenges["a10_6"] = Challenge{
		Title:       "Неправильная обработка исключений",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "Ошибка обрабатывается, но информация о системе раскрывается (путь файла, пользователь, права).",
		Task:        "Попробуйте прочитать файл и получите информацию о системе в ошибке.",
		Hint:        "💡 Попробуйте запросить /api/v1/file/read?file=secret.txt",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/file/read?file=secret.txt" target="_blank" class="api-endpoint">/api/v1/file/read?file=secret.txt</a></p>
				<form method="GET" action="/challenge/a10/6">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая информация о системе была раскрыта? (напишите: path или user или permissions)</label>
						<input type="text" name="info" placeholder="например: path" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			info := strings.ToLower(r.URL.Query().Get("info"))
			return strings.Contains(info, "path") || strings.Contains(info, "user") || strings.Contains(info, "permissions") || strings.Contains(info, "путь")
		},
	}
	
	challenges["a10_7"] = Challenge{
		Title:       "Race condition в обработке ошибок",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Сложный",
		Description: "Ошибки обрабатываются небезопасно в конкурентной среде, что может вызвать race condition.",
		Task:        "Отправьте несколько одновременных запросов и убедитесь, что обработка не потокобезопасна.",
		Hint:        "💡 Отправьте несколько POST запросов на /api/v1/concurrent одновременно",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/concurrent" target="_blank" class="api-endpoint">/api/v1/concurrent</a></p>
				<form method="GET" action="/challenge/a10/7">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какая проблема возможна? (напишите: race condition или гонка)</label>
						<input type="text" name="problem" placeholder="например: race condition" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			problem := strings.ToLower(r.URL.Query().Get("problem"))
			return strings.Contains(problem, "race") || strings.Contains(problem, "condition") || strings.Contains(problem, "гонка")
		},
	}
	
	challenges["a10_8"] = Challenge{
		Title:       "Утечка информации через таймауты",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Сложный",
		Description: "Разное время ответа раскрывает информацию (долгий ответ означает, что пользователь существует).",
		Task:        "Проверьте существование пользователя admin по времени ответа (timing attack).",
		Hint:        "💡 Попробуйте запросить /api/v1/user/check?username=admin и /api/v1/user/check?username=unknown",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/user/check?username=admin" target="_blank" class="api-endpoint">/api/v1/user/check?username=admin</a></p>
				<form method="GET" action="/challenge/a10/8">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Какой тип атаки вы использовали? (напишите: timing attack или атака по времени)</label>
						<input type="text" name="attack" placeholder="например: timing attack" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			attack := strings.ToLower(r.URL.Query().Get("attack"))
			return strings.Contains(attack, "timing") || strings.Contains(attack, "время") || strings.Contains(attack, "таймаут")
		},
	}
	
	challenges["a10_9"] = Challenge{
		Title:       "Небезопасная обработка null значений",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "Нет проверки на null/пустое значение, что может вызвать панику.",
		Task:        "Отправьте запрос с пустым параметром data и убедитесь, что проверка не выполняется.",
		Hint:        "💡 Попробуйте запросить /api/v1/data/process?data=",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/data/process?data=" target="_blank" class="api-endpoint">/api/v1/data/process?data=</a></p>
				<form method="GET" action="/challenge/a10/9">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Проверка на null выполняется? (напишите: no или нет)</label>
						<input type="text" name="null_check" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			check := strings.ToLower(r.URL.Query().Get("null_check"))
			return check == "no" || check == "нет" || check == "n"
		},
	}
	
	challenges["a10_10"] = Challenge{
		Title:       "Отсутствие graceful degradation",
		Category:    "A10: Mishandling of Exceptional Conditions",
		Difficulty:  "Средний",
		Description: "При ошибке сервис полностью падает, нет механизмов отказоустойчивости.",
		Task:        "Проверьте статус сервиса и убедитесь, что при ошибке БД весь сервис недоступен.",
		Hint:        "💡 Попробуйте запросить /api/v1/service/status",
		FormHTML: `
			<div class="card">
				<h2>Попробуйте эксплуатировать уязвимость</h2>
				<p>Эндпоинт: <a href="/api/v1/service/status" target="_blank" class="api-endpoint">/api/v1/service/status</a></p>
				<form method="GET" action="/challenge/a10/10">
					<input type="hidden" name="check" value="1">
					<div class="form-group">
						<label>Есть ли механизмы отказоустойчивости? (напишите: no или нет)</label>
						<input type="text" name="fallback" placeholder="например: no" required>
					</div>
					<button type="submit" class="btn">Проверить решение</button>
				</form>
			</div>
		`,
		CheckFunc: func(r *http.Request) bool {
			fallback := strings.ToLower(r.URL.Query().Get("fallback"))
			return fallback == "no" || fallback == "нет" || fallback == "n"
		},
	}
	
	return challenges
}

