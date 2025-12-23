package endpoints

import "net/http"

// Страница с объяснениями уязвимостей
func explanationsPage(w http.ResponseWriter, r *http.Request) {
	html := renderPage("Объяснение уязвимостей OWASP Top 10:2025", `
		<div class="card">
			<h2>Введение</h2>
			<p>Эта страница содержит подробные объяснения каждой уязвимости из OWASP Top 10:2025 с примерами кода из данного приложения.</p>
		</div>

		<div class="card">
			<h2>A01: Broken Access Control (Нарушение контроля доступа)</h2>
			
			<h3>Уязвимость 1: IDOR (Insecure Direct Object Reference)</h3>
			<p><strong>Проблема:</strong> Пользователь может получить доступ к данным других пользователей, просто изменив ID в URL.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a01_endpoints.go:14-38)
func apiV1UsersID(w http.ResponseWriter, r *http.Request) {
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
			<p><strong>Почему это происходит:</strong> Код не проверяет, имеет ли текущий пользователь право доступа к запрашиваемому ID. Любой может изменить URL с <code>/api/v1/users/1</code> на <code>/api/v1/users/2</code> и получить чужие данные.</p>
			<p><strong>Как исправить:</strong> Добавить проверку: <code>if currentUserID != requestedUserID { return error }</code></p>

			<h3>Уязвимость 2: Обход авторизации через параметр</h3>
			<p><strong>Проблема:</strong> Админские права проверяются через GET-параметр, который можно легко подделать.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a01_endpoints.go:42-56)
func apiV1AdminUsers(w http.ResponseWriter, r *http.Request) {
    isAdmin := r.URL.Query().Get("is_admin")
    
    if isAdmin == "true" || isAdmin == "1" {
        // Показать всех пользователей
    }
}</code></pre>
			<p><strong>Почему это происходит:</strong> Параметры запроса контролируются клиентом и могут быть легко изменены. Злоумышленник может просто добавить <code>?is_admin=true</code> к любому URL.</p>
			<p><strong>Как исправить:</strong> Проверять права через серверную сессию или JWT токен, а не через параметры запроса.</p>

			<h3>Уязвимость 3: Небезопасный редирект</h3>
			<p><strong>Проблема:</strong> Приложение перенаправляет пользователя на любой URL без проверки.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a01_endpoints.go:65-99)
func apiV1AuthLoginRedirect(w http.ResponseWriter, r *http.Request) {
    redirect := r.FormValue("redirect")
    // УЯЗВИМОСТЬ: Редирект на любой URL без проверки
    http.Redirect(w, r, redirect, 302)
}</code></pre>
			<p><strong>Почему это происходит:</strong> URL для редиректа берется напрямую из пользовательского ввода без валидации. Злоумышленник может создать ссылку, которая перенаправит на фишинговый сайт.</p>
			<p><strong>Как исправить:</strong> Проверять, что URL редиректа принадлежит вашему домену: <code>if !strings.HasPrefix(redirect, "/") || strings.Contains(redirect, "://") { return error }</code></p>
		</div>

		<div class="card">
			<h2>A02: Security Misconfiguration (Неправильная конфигурация безопасности)</h2>
			
			<h3>Уязвимость 1: Открытый .env файл</h3>
			<p><strong>Проблема:</strong> Файл с секретными данными доступен через веб-сервер.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a02_endpoints.go:12-22)
func apiV1ConfigEnv(w http.ResponseWriter, r *http.Request) {
    // УЯЗВИМОСТЬ: .env файл доступен через веб-сервер
    w.Write([]byte("DATABASE_URL=postgresql://admin:password@db:5432\nAWS_SECRET_KEY=secret123"))
}</code></pre>
			<p><strong>Почему это происходит:</strong> Веб-сервер настроен так, что отдает файлы из корневой директории, включая конфигурационные файлы. Это часто происходит из-за неправильной настройки nginx/apache.</p>
			<p><strong>Как исправить:</strong> Настроить веб-сервер так, чтобы он блокировал доступ к файлам, начинающимся с точки, или хранить секреты в переменных окружения, а не в файлах.</p>

			<h3>Уязвимость 2: Отладочная информация в production</h3>
			<p><strong>Проблема:</strong> При ошибках показывается полный stack trace с чувствительными данными.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a02_endpoints.go:24-48)
func apiV1UsersSearchDebug(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // УЯЗВИМОСТЬ: Показываем полный stack trace и SQL запрос
    w.Write([]byte("Error: Empty query parameter\nStack Trace: UserService.java:142\nSQL Query: SELECT * FROM users WHERE name LIKE '%'\nDatabase: postgresql://prod-db.internal:5432"))
}</code></pre>
			<p><strong>Почему это происходит:</strong> В production-окружении включен режим отладки или не настроена правильная обработка ошибок. Это раскрывает внутреннюю структуру приложения и данные.</p>
			<p><strong>Как исправить:</strong> В production показывать только общие сообщения об ошибках, а детали логировать в безопасное место.</p>
		</div>

		<div class="card">
			<h2>A03: Software Supply Chain Failures (Проблемы цепочки поставок ПО)</h2>
			
			<h3>Уязвимость 1: Установка пакетов без проверки</h3>
			<p><strong>Проблема:</strong> Пакеты устанавливаются без проверки цифровой подписи и целостности.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a03_endpoints.go:13-42)
func apiV1PackagesInstall(w http.ResponseWriter, r *http.Request) {
    packageName := r.FormValue("package")
    
    // УЯЗВИМОСТЬ: Устанавливаем пакет без проверки подписи
    sendJSON(w, map[string]interface{}{
        "message": fmt.Sprintf("Package %s installed without signature verification", packageName),
    })
}</code></pre>
			<p><strong>Почему это происходит:</strong> Менеджеры пакетов (npm, pip, go get) по умолчанию не проверяют подписи. Если репозиторий скомпрометирован, можно установить вредоносный пакет.</p>
			<p><strong>Как исправить:</strong> Использовать проверку checksum (go.sum, package-lock.json) и проверять подписи пакетов перед установкой.</p>

			<h3>Уязвимость 2: Command Injection</h3>
			<p><strong>Проблема:</strong> Пользовательский ввод передается напрямую в системную команду.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a03_endpoints.go:61-90)
func apiV1Build(w http.ResponseWriter, r *http.Request) {
    script := r.FormValue("script")
    
    // УЯЗВИМОСТЬ: Выполняем произвольную команду
    out, _ := exec.Command("sh", "-c", script).Output()
    sendJSON(w, map[string]interface{}{"output": string(out)})
}</code></pre>
			<p><strong>Почему это происходит:</strong> Код использует <code>exec.Command</code> с пользовательским вводом без санитизации. Злоумышленник может выполнить любую команду, добавив <code>; cat /etc/passwd</code>.</p>
			<p><strong>Как исправить:</strong> Использовать whitelist разрешенных команд или параметризованные вызовы вместо конкатенации строк.</p>
		</div>

		<div class="card">
			<h2>A04: Cryptographic Failures (Криптографические ошибки)</h2>
			
			<h3>Уязвимость 1: Хранение паролей в открытом виде</h3>
			<p><strong>Проблема:</strong> Пароли хранятся в базе данных без хеширования.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a04_endpoints.go:15-39)
func apiV1UsersPasswordPlain(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    passwords := map[string]string{
        "1": "password123",  // Пароль в открытом виде!
        "2": "admin123",
    }
    
    if pass, ok := passwords[userID]; ok {
        sendJSON(w, map[string]interface{}{"password": pass})
    }
}</code></pre>
			<p><strong>Почему это происходит:</strong> Разработчики забывают хешировать пароли перед сохранением. Если база данных скомпрометирована, все пароли будут доступны.</p>
			<p><strong>Как исправить:</strong> Использовать bcrypt, argon2 или scrypt для хеширования паролей: <code>hashedPassword := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)</code></p>

			<h3>Уязвимость 2: Использование MD5</h3>
			<p><strong>Проблема:</strong> MD5 - устаревший и небезопасный алгоритм хеширования.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a04_endpoints.go:40-70)
func apiV1AuthHash(w http.ResponseWriter, r *http.Request) {
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Используем MD5 для хеширования (легко взломать)
    hash := md5.Sum([]byte(password))
    sendJSON(w, map[string]interface{}{"hash": fmt.Sprintf("%x", hash)})
}</code></pre>
			<p><strong>Почему это происходит:</strong> MD5 был взломан много лет назад. Можно найти пароль по хешу за секунды используя rainbow tables или брутфорс.</p>
			<p><strong>Как исправить:</strong> Использовать современные алгоритмы: SHA-256 для общих целей, bcrypt/argon2 для паролей.</p>
		</div>

		<div class="card">
			<h2>A05: Injection (Инъекции)</h2>
			
			<h3>Уязвимость 1: SQL Injection</h3>
			<p><strong>Проблема:</strong> Пользовательский ввод напрямую вставляется в SQL запрос.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a05_endpoints.go:13-35)
func apiV1UsersSearchSQL(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // УЯЗВИМОСТЬ: SQL запрос формируется напрямую из пользовательского ввода
    sqlQuery := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", query)
    
    sendJSON(w, map[string]interface{}{"sql_query": sqlQuery})
}</code></pre>
			<p><strong>Почему это происходит:</strong> Конкатенация строк для создания SQL запроса позволяет злоумышленнику вставить свой SQL код. Например, <code>q=' OR '1'='1</code> превратит запрос в <code>SELECT * FROM users WHERE name LIKE '%' OR '1'='1'</code>, что вернет всех пользователей.</p>
			<p><strong>Как исправить:</strong> Использовать параметризованные запросы (prepared statements): <code>db.Query("SELECT * FROM users WHERE name LIKE ?", query)</code></p>

			<h3>Уязвимость 2: Command Injection</h3>
			<p><strong>Проблема:</strong> Пользовательский ввод передается в системную команду.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a05_endpoints.go:37-65)
func apiV1NetworkPing(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue("host")
    
    // УЯЗВИМОСТЬ: Выполняем команду без санитизации
    cmd := exec.Command("ping", "-c", "4", host)
    out, _ := cmd.Output()
}</code></pre>
			<p><strong>Почему это происходит:</strong> Если передать <code>host=8.8.8.8; cat /etc/passwd</code>, выполнится не только ping, но и команда cat. Shell интерпретирует точку с запятой как разделитель команд.</p>
			<p><strong>Как исправить:</strong> Валидировать ввод (только IP адреса) или использовать параметризованные команды без shell.</p>

			<h3>Уязвимость 3: XSS (Cross-Site Scripting)</h3>
			<p><strong>Проблема:</strong> Пользовательский ввод выводится без экранирования.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a05_endpoints.go:67-104)
func apiV1Comments(w http.ResponseWriter, r *http.Request) {
    comment := r.FormValue("comment")
    user := r.FormValue("user")
    
    // УЯЗВИМОСТЬ: Комментарий выводится без экранирования
    html := fmt.Sprintf("&lt;p&gt;&lt;strong&gt;%s:&lt;/strong&gt; %s&lt;/p&gt;", user, comment)
    w.Write([]byte(html))
}</code></pre>
			<p><strong>Почему это происходит:</strong> Если пользователь введет <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>, браузер выполнит этот JavaScript код. Это может привести к краже сессий или перенаправлению на фишинговые сайты.</p>
			<p><strong>Как исправить:</strong> Экранировать HTML: <code>html.EscapeString(comment)</code> или использовать шаблоны с автоматическим экранированием.</p>
		</div>

		<div class="card">
			<h2>A06: Insecure Design (Небезопасный дизайн)</h2>
			
			<h3>Уязвимость 1: Отсутствие rate limiting</h3>
			<p><strong>Проблема:</strong> Нет ограничения на количество запросов от одного IP.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a06_endpoints.go:13-47)
func apiV1AuthLoginNoRateLimit(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет ограничения на количество попыток входа
    // Можно отправлять тысячи запросов в секунду
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			<p><strong>Почему это происходит:</strong> Приложение не отслеживает количество запросов от одного источника. Это позволяет брутфорсить пароли или выполнить DoS атаку.</p>
			<p><strong>Как исправить:</strong> Использовать rate limiting (например, 5 попыток входа в минуту с одного IP) с помощью Redis или специализированных библиотек.</p>

			<h3>Уязвимость 2: Слабая валидация</h3>
			<p><strong>Проблема:</strong> Email не проверяется на корректность формата.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a06_endpoints.go:48-76)
func apiV1UsersRegister(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    
    // УЯЗВИМОСТЬ: Нет проверки формата email
    // Принимается любая строка
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			<p><strong>Почему это происходит:</strong> Разработчики полагаются на клиентскую валидацию или забывают валидировать на сервере. Это может привести к проблемам с данными или SQL injection.</p>
			<p><strong>Как исправить:</strong> Валидировать на сервере: <code>matched, _ := regexp.MatchString("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email)</code></p>
		</div>

		<div class="card">
			<h2>A07: Authentication Failures (Ошибки аутентификации)</h2>
			
			<h3>Уязвимость 1: Слабые пароли по умолчанию</h3>
			<p><strong>Проблема:</strong> Система использует стандартные пароли, которые не были изменены.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a07_endpoints.go:17-59)
var userDB = map[string]string{
    "admin@company.com": "admin123",  // Пароль по умолчанию!
    "user@company.com": "password",
}

func apiV1AuthDefaultLogin(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    if userDB[email] == password {
        sendJSON(w, map[string]interface{}{"status": "success"})
    }
}</code></pre>
			<p><strong>Почему это происходит:</strong> При первом запуске системы создаются учетные записи с известными паролями. Если администратор не меняет их, злоумышленник может легко войти.</p>
			<p><strong>Как исправить:</strong> Требовать смену пароля при первом входе или генерировать случайные пароли для новых пользователей.</p>

			<h3>Уязвимость 2: Отсутствие блокировки после неудачных попыток</h3>
			<p><strong>Проблема:</strong> Можно бесконечно пытаться угадать пароль.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a07_endpoints.go:60-100)
func apiV1AuthBruteforce(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Нет блокировки, можно брутфорсить
    if userDB[email] == password {
        sendJSON(w, map[string]interface{}{"status": "success"})
    } else {
        sendJSON(w, map[string]interface{}{"status": "error"})
    }
}</code></pre>
			<p><strong>Почему это происходит:</strong> Код не отслеживает количество неудачных попыток. Злоумышленник может автоматизировать перебор паролей.</p>
			<p><strong>Как исправить:</strong> Блокировать аккаунт после 5 неудачных попыток на 15 минут или использовать CAPTCHA.</p>
		</div>

		<div class="card">
			<h2>A08: Data Integrity Failures (Нарушения целостности данных)</h2>
			
			<h3>Уязвимость 1: Отсутствие проверки подписи</h3>
			<p><strong>Проблема:</strong> Файлы загружаются без проверки цифровой подписи.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a08_endpoints.go:12-41)
func apiV1UpdateUpload(w http.ResponseWriter, r *http.Request) {
    file := r.FormValue("file")
    
    // УЯЗВИМОСТЬ: Файл загружается без проверки цифровой подписи
    sendJSON(w, map[string]interface{}{
        "message": fmt.Sprintf("File %s uploaded without signature verification", file),
    })
}</code></pre>
			<p><strong>Почему это происходит:</strong> Приложение доверяет файлам без проверки их происхождения. Если злоумышленник скомпрометирует сервер обновлений, он может загрузить вредоносный код.</p>
			<p><strong>Как исправить:</strong> Проверять цифровую подпись файла перед установкой: <code>if !verifySignature(file, signature) { return error }</code></p>
		</div>

		<div class="card">
			<h2>A09: Logging Failures (Ошибки логирования)</h2>
			
			<h3>Уязвимость 1: Чувствительные данные в логах</h3>
			<p><strong>Проблема:</strong> Пароли и другие секреты логируются в открытом виде.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a09_endpoints.go:24-59)
func apiV1AuthLoginLogSensitive(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    
    // УЯЗВИМОСТЬ: Учетные данные логируются в открытом виде
    fmt.Printf("[LOG] Login attempt - email: %s, password: %s\n", email, password)
    
    sendJSON(w, map[string]interface{}{"status": "success"})
}</code></pre>
			<p><strong>Почему это происходит:</strong> Разработчики логируют все данные для отладки и забывают убрать это в production. Если логи доступны злоумышленнику, он получит все пароли.</p>
			<p><strong>Как исправить:</strong> Никогда не логировать пароли. Логировать только факт попытки входа: <code>log.Printf("Login attempt for user: %s, result: %s", email, result)</code></p>
		</div>

		<div class="card">
			<h2>A10: Exception Handling (Обработка исключений)</h2>
			
			<h3>Уязвимость 1: Раскрытие информации в ошибках</h3>
			<p><strong>Проблема:</strong> При ошибке показывается полный stack trace с внутренними деталями.</p>
			<pre class="response"><code>// УЯЗВИМЫЙ КОД (a10_endpoints.go:14-44)
func apiV1UsersGet(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    
    if userID == "" {
        // УЯЗВИМОСТЬ: Полная информация об ошибке раскрывается
        w.Write([]byte("Error: user_id parameter is required\nStack Trace: UserService.java:142\nDatabase: postgresql://prod-db.internal:5432\nConnection Pool: 45/50 active"))
    }
}</code></pre>
			<p><strong>Почему это происходит:</strong> В production включен режим отладки или не настроена правильная обработка ошибок. Stack trace раскрывает структуру кода, версии библиотек и пути к файлам.</p>
			<p><strong>Как исправить:</strong> В production показывать только общие сообщения: <code>w.Write([]byte("Произошла ошибка. Обратитесь в поддержку."))</code>, а детали логировать на сервере.</p>
		</div>

		<div class="card">
			<h2>Заключение</h2>
			<p>Все эти уязвимости демонстрируют распространенные ошибки в веб-разработке. Главные принципы безопасности:</p>
			<ul>
				<li><strong>Не доверяйте пользовательскому вводу</strong> - всегда валидируйте и санитизируйте</li>
				<li><strong>Принцип наименьших привилегий</strong> - пользователь должен иметь доступ только к своим данным</li>
				<li><strong>Защита в глубину</strong> - используйте несколько уровней защиты</li>
				<li><strong>Не раскрывайте внутреннюю информацию</strong> - ошибки должны быть общими</li>
				<li><strong>Используйте современные криптографические алгоритмы</strong> - не используйте устаревшие методы</li>
			</ul>
			<p>Изучите код каждого эндпоинта в этом приложении, чтобы понять, как работают эти уязвимости на практике.</p>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

