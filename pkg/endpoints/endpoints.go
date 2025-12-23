package endpoints

import "net/http"

type endpoints struct {
	addr string
	r    *http.ServeMux
}

func New(addr string, r *http.ServeMux) *endpoints {
	return &endpoints{addr: addr, r: r}
}

func (e *endpoints) FillEndpoints() {
	// Главная страница
	e.r.HandleFunc("/", index)
	// Страница с объяснениями
	e.r.HandleFunc("/explanations", explanationsPage)
	// Страницы с заданиями для уязвимостей
	e.r.HandleFunc("/challenge/", challengePage)

	// A01: Broken Access Control (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/users/", apiV1UsersID)
	e.r.HandleFunc("/api/v1/admin/users", apiV1AdminUsers)
	e.r.HandleFunc("/api/v1/auth/login", apiV1AuthLoginRedirect)
	e.r.HandleFunc("/api/v1/auth/verify", apiV1AuthVerifyJWT)
	e.r.HandleFunc("/api/v1/files", apiV1Files)
	e.r.HandleFunc("/api/v1/admin/config", apiV1AdminConfig)
	e.r.HandleFunc("/api/v1/user/profile", apiV1UserProfile)
	e.r.HandleFunc("/api/v1/payment/transfer", apiV1PaymentTransferRace)
	e.r.HandleFunc("/api/v1/admin/dashboard", apiV1AdminDashboard)
	e.r.HandleFunc("/api/v1/user/settings", apiV1UserSettings)

	// A02: Security Misconfiguration (10 эндпоинтов)
	e.r.HandleFunc("/.env", apiV1ConfigEnv)
	e.r.HandleFunc("/api/v1/debug/users/search", apiV1UsersSearchDebug)
	e.r.HandleFunc("/metrics", apiV1Metrics)
	e.r.HandleFunc("/.git/config", apiV1GitConfig)
	e.r.HandleFunc("/api/v1/api/data", apiV1ApiData)
	e.r.HandleFunc("/api/v1/health", apiV1Health)
	e.r.HandleFunc("/api/v1/auth/session", apiV1AuthSession)
	e.r.HandleFunc("/api/v1/backup", apiV1Backup)
	e.r.HandleFunc("/api/v1/logs", apiV1Logs)
	e.r.HandleFunc("/api/v1/config/database", apiV1ConfigDatabase)

	// A03: Software Supply Chain (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/packages/install", apiV1PackagesInstall)
	e.r.HandleFunc("/api/v1/dependencies/update", apiV1DependenciesUpdate)
	e.r.HandleFunc("/api/v1/build", apiV1Build)
	e.r.HandleFunc("/api/v1/update", apiV1Update)
	e.r.HandleFunc("/api/v1/dependencies/list", apiV1DependenciesList)
	e.r.HandleFunc("/api/v1/packages/search", apiV1PackagesSearch)
	e.r.HandleFunc("/api/v1/repo/clone", apiV1RepoClone)
	e.r.HandleFunc("/api/v1/webhook/update", apiV1WebhookUpdate)
	e.r.HandleFunc("/api/v1/package/registry", apiV1PackageRegistry)
	e.r.HandleFunc("/api/v1/dependencies/tree", apiV1DependenciesTree)

	// A04: Cryptographic Failures (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/users/password", apiV1UsersPasswordPlain)
	e.r.HandleFunc("/api/v1/auth/hash", apiV1AuthHash)
	e.r.HandleFunc("/api/v1/api/sign", apiV1ApiSign)
	e.r.HandleFunc("/api/v1/encrypt", apiV1Encrypt)
	e.r.HandleFunc("/api/v1/config/keys", apiV1ConfigKeys)
	e.r.HandleFunc("/api/v1/payment/process", apiV1PaymentProcessHTTP)
	e.r.HandleFunc("/api/v1/auth/token", apiV1AuthToken)
	e.r.HandleFunc("/api/v1/key/exchange", apiV1KeyExchange)
	e.r.HandleFunc("/api/v1/external/api", apiV1ExternalApi)
	e.r.HandleFunc("/api/v1/api/call", apiV1ApiCall)

	// A05: Injection (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/users/search", apiV1UsersSearchSQL)
	e.r.HandleFunc("/api/v1/network/ping", apiV1NetworkPing)
	e.r.HandleFunc("/api/v1/comments", apiV1Comments)
	e.r.HandleFunc("/api/v1/ldap/search", apiV1LdapSearch)
	e.r.HandleFunc("/api/v1/users/find", apiV1UsersFind)
	e.r.HandleFunc("/api/v1/render", apiV1Render)
	e.r.HandleFunc("/api/v1/xml/parse", apiV1XmlParse)
	e.r.HandleFunc("/api/v1/files/download", apiV1FilesDownload)
	e.r.HandleFunc("/api/v1/webhook", apiV1Webhook)
	e.r.HandleFunc("/api/v1/execute", apiV1Execute)

	// A06: Insecure Design (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/a06/auth/login", apiV1AuthLoginNoRateLimit)
	e.r.HandleFunc("/api/v1/users/register", apiV1UsersRegister)
	e.r.HandleFunc("/api/v1/contact", apiV1Contact)
	e.r.HandleFunc("/api/v1/a06/users/delete", apiV1UsersDeleteGET)
	e.r.HandleFunc("/api/v1/a06/payment/transfer", apiV1PaymentTransferNoCheck)
	e.r.HandleFunc("/api/v1/a06/users/password", apiV1UsersPasswordWeak)
	e.r.HandleFunc("/api/v1/a06/auth/verify", apiV1AuthVerifyNo2FA)
	e.r.HandleFunc("/api/v1/a06/session/create", apiV1SessionCreateInsecure)
	e.r.HandleFunc("/api/v1/admin/action", apiV1AdminAction)
	e.r.HandleFunc("/api/v1/a06/password/reset", apiV1PasswordResetInsecure)

	// A07: Authentication Failures (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/auth/default/login", apiV1AuthDefaultLogin)
	e.r.HandleFunc("/api/v1/auth/bruteforce", apiV1AuthBruteforce)
	e.r.HandleFunc("/api/v1/a07/users/password", apiV1UsersPasswordDB)
	e.r.HandleFunc("/api/v1/session/verify", apiV1SessionVerify)
	e.r.HandleFunc("/api/v1/session/info", apiV1SessionInfo)
	e.r.HandleFunc("/api/v1/a07/password/reset", apiV1PasswordResetAuth)
	e.r.HandleFunc("/api/v1/auth/login/no2fa", apiV1AuthLoginNo2FA)
	e.r.HandleFunc("/api/v1/a07/session/create", apiV1SessionCreateForgery)
	e.r.HandleFunc("/api/v1/session/validate", apiV1SessionValidate)
	e.r.HandleFunc("/api/v1/auth/login/log", apiV1AuthLoginLog)

	// A08: Data Integrity Failures (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/update/upload", apiV1UpdateUpload)
	e.r.HandleFunc("/api/v1/update/install", apiV1UpdateInstall)
	e.r.HandleFunc("/api/v1/data/save", apiV1DataSave)
	e.r.HandleFunc("/api/v1/dependencies/install", apiV1DependenciesInstall)
	e.r.HandleFunc("/api/v1/files/upload", apiV1FilesUpload)
	e.r.HandleFunc("/api/v1/cicd/deploy", apiV1CICDDeploy)
	e.r.HandleFunc("/api/v1/repo/pull", apiV1RepoPull)
	e.r.HandleFunc("/api/v1/code/execute", apiV1CodeExecute)
	e.r.HandleFunc("/api/v1/certificate/verify", apiV1CertificateVerify)
	e.r.HandleFunc("/api/v1/file/check", apiV1FileCheck)

	// A09: Logging Failures (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/a09/users/delete", apiV1UsersDeleteNoLog)
	e.r.HandleFunc("/api/v1/a09/auth/login", apiV1AuthLoginLogSensitive)
	e.r.HandleFunc("/api/v1/system/status", apiV1SystemStatus)
	e.r.HandleFunc("/api/v1/a09/payment/process", apiV1PaymentProcessInsufficientLog)
	e.r.HandleFunc("/api/v1/auth/failed/login", apiV1AuthFailedLogin)
	e.r.HandleFunc("/api/v1/logs/access", apiV1LogsAccess)
	e.r.HandleFunc("/api/v1/events/list", apiV1EventsList)
	e.r.HandleFunc("/api/v1/action/execute", apiV1ActionExecute)
	e.r.HandleFunc("/api/v1/logs/analyze", apiV1LogsAnalyze)
	e.r.HandleFunc("/api/v1/logs/storage", apiV1LogsStorage)

	// A10: Exception Handling (10 эндпоинтов)
	e.r.HandleFunc("/api/v1/users/get", apiV1UsersGet)
	e.r.HandleFunc("/api/v1/calculate", apiV1Calculate)
	e.r.HandleFunc("/api/v1/database/query", apiV1DatabaseQuery)
	e.r.HandleFunc("/api/v1/process", apiV1Process)
	e.r.HandleFunc("/api/v1/transfer", apiV1Transfer)
	e.r.HandleFunc("/api/v1/file/read", apiV1FileRead)
	e.r.HandleFunc("/api/v1/concurrent", apiV1Concurrent)
	e.r.HandleFunc("/api/v1/user/check", apiV1UserCheck)
	e.r.HandleFunc("/api/v1/data/process", apiV1DataProcess)
	e.r.HandleFunc("/api/v1/service/status", apiV1ServiceStatus)
}

func (e *endpoints) ListenAndServe() error {
	return http.ListenAndServe(e.addr, e.r)
}

// Главная страница с навигацией
func index(w http.ResponseWriter, r *http.Request) {
	html := renderPage("Документация API", `
		<div class="card">
			<p><a href="/explanations" class="btn">📚 Читать объяснения уязвимостей с примерами кода</a></p>
		</div>
		
		<div class="card">
			<h2>A01: Broken Access Control (Нарушение контроля доступа)</h2>
			<ul>
				<li><a href="/challenge/a01/1" class="api-endpoint">🔓 Задание 1: IDOR</a> - Получите данные другого пользователя</li>
				<li><a href="/challenge/a01/2" class="api-endpoint">🔓 Задание 2: Обход через параметр</a> - Получите админский доступ</li>
				<li><a href="/challenge/a01/3" class="api-endpoint">🔓 Задание 3: Небезопасный редирект</a> - Создайте фишинговую ссылку</li>
				<li><a href="/challenge/a01/4" class="api-endpoint">🔓 Задание 4: Слабая проверка JWT</a> - Получите админский доступ через токен</li>
				<li><a href="/challenge/a01/5" class="api-endpoint">🔓 Задание 5: Прямой доступ к файлам</a> - Получите конфигурационные файлы</li>
				<li><a href="/challenge/a01/6" class="api-endpoint">🔓 Задание 6: Обход через заголовки</a> - Используйте заголовок X-Admin</li>
				<li><a href="/challenge/a01/7" class="api-endpoint">🔓 Задание 7: Неправильная настройка CORS</a> - Получите данные через CORS</li>
				<li><a href="/challenge/a01/8" class="api-endpoint">🔓 Задание 8: Race condition</a> - Отправьте одновременные запросы</li>
				<li><a href="/challenge/a01/9" class="api-endpoint">🔓 Задание 9: Прямой доступ к админке</a> - Откройте админ панель</li>
				<li><a href="/challenge/a01/10" class="api-endpoint">🔓 Задание 10: Параметр обхода</a> - Используйте bypass_auth</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A02: Security Misconfiguration (Неправильная конфигурация)</h2>
			<ul>
				<li><a href="/challenge/a02/1" class="api-endpoint">🔓 Задание 1: Открытый .env</a> - Получите секретные ключи</li>
				<li><a href="/challenge/a02/2" class="api-endpoint">🔓 Задание 2: Отладочная информация</a> - Получите stack trace</li>
				<li><a href="/challenge/a02/3" class="api-endpoint">🔓 Задание 3: Открытые метрики</a> - Получите Prometheus метрики</li>
				<li><a href="/challenge/a02/4" class="api-endpoint">🔓 Задание 4: Открытый Git</a> - Получите .git/config</li>
				<li><a href="/challenge/a02/5" class="api-endpoint">🔓 Задание 5: Слабая конфигурация CORS</a> - Используйте внешний домен</li>
				<li><a href="/challenge/a02/6" class="api-endpoint">🔓 Задание 6: Версия в заголовках</a> - Получите информацию о технологиях</li>
				<li><a href="/challenge/a02/7" class="api-endpoint">🔓 Задание 7: Небезопасные сессии</a> - Проверьте флаги сессии</li>
				<li><a href="/challenge/a02/8" class="api-endpoint">🔓 Задание 8: Открытые backup файлы</a> - Получите backup базы данных</li>
				<li><a href="/challenge/a02/9" class="api-endpoint">🔓 Задание 9: Открытые логи</a> - Получите логи приложения</li>
				<li><a href="/challenge/a02/10" class="api-endpoint">🔓 Задание 10: Конфигурация БД</a> - Получите пароли базы данных</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A03: Software Supply Chain (Проблемы цепочки поставок ПО)</h2>
			<ul>
				<li><a href="/challenge/a03/1" class="api-endpoint">🔓 Задание 1: Установка без проверки</a> - Установите пакет без подписи</li>
				<li><a href="/challenge/a03/2" class="api-endpoint">🔓 Задание 2: Небезопасный источник</a> - Загрузите с внешнего URL</li>
				<li><a href="/challenge/a03/3" class="api-endpoint">🔓 Задание 3: Выполнение команд</a> - Выполните произвольную команду</li>
				<li><a href="/challenge/a03/4" class="api-endpoint">🔓 Задание 4: Обновление без checksum</a> - Обновите без проверки</li>
				<li><a href="/challenge/a03/5" class="api-endpoint">🔓 Задание 5: Устаревшие библиотеки</a> - Найдите CVE уязвимости</li>
				<li><a href="/challenge/a03/6" class="api-endpoint">🔓 Задание 6: Typosquatting</a> - Установите пакет с опечаткой</li>
				<li><a href="/challenge/a03/7" class="api-endpoint">🔓 Задание 7: Компрометированный репозиторий</a> - Клонируйте без проверки</li>
				<li><a href="/challenge/a03/8" class="api-endpoint">🔓 Задание 8: Небезопасный webhook</a> - Обновите через webhook</li>
				<li><a href="/challenge/a03/9" class="api-endpoint">🔓 Задание 9: Подмена DNS</a> - Загрузите без проверки DNS</li>
				<li><a href="/challenge/a03/10" class="api-endpoint">🔓 Задание 10: Транзитивные зависимости</a> - Найдите уязвимости в зависимостях</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A04: Cryptographic Failures (Криптографические ошибки)</h2>
			<ul>
				<li><a href="/challenge/a04/1" class="api-endpoint">🔓 Задание 1: Пароли в открытом виде</a> - Получите пароль пользователя</li>
				<li><a href="/challenge/a04/2" class="api-endpoint">🔓 Задание 2: Использование MD5</a> - Взломайте MD5 хеш</li>
				<li><a href="/challenge/a04/3" class="api-endpoint">🔓 Задание 3: Использование SHA1</a> - Создайте подпись SHA1</li>
				<li><a href="/challenge/a04/4" class="api-endpoint">🔓 Задание 4: Слабый ключ шифрования</a> - Найдите длину ключа</li>
				<li><a href="/challenge/a04/5" class="api-endpoint">🔓 Задание 5: API ключи в коде</a> - Получите секретные ключи</li>
				<li><a href="/challenge/a04/6" class="api-endpoint">🔓 Задание 6: HTTP вместо HTTPS</a> - Обработайте платеж через HTTP</li>
				<li><a href="/challenge/a04/7" class="api-endpoint">🔓 Задание 7: Слабая генерация токенов</a> - Получите предсказуемый токен</li>
				<li><a href="/challenge/a04/8" class="api-endpoint">🔓 Задание 8: Небезопасный обмен ключами</a> - Получите ключ в открытом виде</li>
				<li><a href="/challenge/a04/9" class="api-endpoint">🔓 Задание 9: Отсутствие проверки сертификата</a> - Выполните MITM атаку</li>
				<li><a href="/challenge/a04/10" class="api-endpoint">🔓 Задание 10: Утечка ключей в логах</a> - Найдите ключ в логах</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A05: Injection (Инъекции)</h2>
			<ul>
				<li><a href="/challenge/a05/1" class="api-endpoint">🔓 Задание 1: SQL Injection</a> - Получите всех пользователей</li>
				<li><a href="/challenge/a05/2" class="api-endpoint">🔓 Задание 2: Command Injection</a> - Выполните системную команду</li>
				<li><a href="/challenge/a05/3" class="api-endpoint">🔓 Задание 3: XSS</a> - Выполните JavaScript код</li>
				<li><a href="/challenge/a05/4" class="api-endpoint">🔓 Задание 4: LDAP Injection</a> - Используйте специальные символы</li>
				<li><a href="/challenge/a05/5" class="api-endpoint">🔓 Задание 5: NoSQL Injection</a> - Используйте операторы MongoDB</li>
				<li><a href="/challenge/a05/6" class="api-endpoint">🔓 Задание 6: Template Injection</a> - Выполните код в шаблоне</li>
				<li><a href="/challenge/a05/7" class="api-endpoint">🔓 Задание 7: XXE</a> - Прочитайте файл через XML</li>
				<li><a href="/challenge/a05/8" class="api-endpoint">🔓 Задание 8: Path Traversal</a> - Прочитайте /etc/passwd</li>
				<li><a href="/challenge/a05/9" class="api-endpoint">🔓 Задание 9: SSRF</a> - Отправьте запрос к localhost</li>
				<li><a href="/challenge/a05/10" class="api-endpoint">🔓 Задание 10: Code Injection</a> - Выполните произвольный код</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A06: Insecure Design (Небезопасный дизайн)</h2>
			<ul>
				<li><a href="/challenge/a06/1" class="api-endpoint">🔓 Задание 1: Отсутствие rate limiting</a> - Выполните брутфорс атаку</li>
				<li><a href="/challenge/a06/2" class="api-endpoint">🔓 Задание 2: Слабая валидация email</a> - Зарегистрируйтесь с невалидным email</li>
				<li><a href="/challenge/a06/3" class="api-endpoint">🔓 Задание 3: Отсутствие CAPTCHA</a> - Отправьте форму без CAPTCHA</li>
				<li><a href="/challenge/a06/4" class="api-endpoint">🔓 Задание 4: Опасные действия через GET</a> - Удалите пользователя через GET</li>
				<li><a href="/challenge/a06/5" class="api-endpoint">🔓 Задание 5: Отсутствие проверки логики</a> - Переведите отрицательную сумму</li>
				<li><a href="/challenge/a06/6" class="api-endpoint">🔓 Задание 6: Слабые требования к паролю</a> - Установите слабый пароль</li>
				<li><a href="/challenge/a06/7" class="api-endpoint">🔓 Задание 7: Отсутствие 2FA</a> - Войдите без двухфакторной аутентификации</li>
				<li><a href="/challenge/a06/8" class="api-endpoint">🔓 Задание 8: Небезопасный дизайн сессий</a> - Создайте сессию без истечения</li>
				<li><a href="/challenge/a06/9" class="api-endpoint">🔓 Задание 9: Отсутствие аудита</a> - Выполните действие без логирования</li>
				<li><a href="/challenge/a06/10" class="api-endpoint">🔓 Задание 10: Небезопасное восстановление пароля</a> - Захватите аккаунт</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A07: Authentication Failures (Ошибки аутентификации)</h2>
			<ul>
				<li><a href="/challenge/a07/1" class="api-endpoint">🔓 Задание 1: Слабые пароли по умолчанию</a> - Войдите с дефолтными данными</li>
				<li><a href="/challenge/a07/2" class="api-endpoint">🔓 Задание 2: Отсутствие блокировки</a> - Выполните брутфорс атаку</li>
				<li><a href="/challenge/a07/3" class="api-endpoint">🔓 Задание 3: Пароли в открытом виде</a> - Получите пароль из БД</li>
				<li><a href="/challenge/a07/4" class="api-endpoint">🔓 Задание 4: Слабая проверка сессии</a> - Используйте произвольный session_id</li>
				<li><a href="/challenge/a07/5" class="api-endpoint">🔓 Задание 5: Сессия не истекает</a> - Проверьте срок действия сессии</li>
				<li><a href="/challenge/a07/6" class="api-endpoint">🔓 Задание 6: Небезопасное восстановление</a> - Получите пароль без проверки</li>
				<li><a href="/challenge/a07/7" class="api-endpoint">🔓 Задание 7: Отсутствие 2FA</a> - Войдите без двухфакторной аутентификации</li>
				<li><a href="/challenge/a07/8" class="api-endpoint">🔓 Задание 8: Подделка сессий</a> - Создайте админскую сессию</li>
				<li><a href="/challenge/a07/9" class="api-endpoint">🔓 Задание 9: Отсутствие проверки IP</a> - Используйте сессию с любого IP</li>
				<li><a href="/challenge/a07/10" class="api-endpoint">🔓 Задание 10: Утечка в логах</a> - Найдите пароль в логах</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A08: Software or Data Integrity Failures (Нарушение целостности ПО и данных)</h2>
			<ul>
				<li><a href="/challenge/a08/1" class="api-endpoint">🔓 Задание 1: Загрузка без проверки подписи</a> - Загрузите файл без подписи</li>
				<li><a href="/challenge/a08/2" class="api-endpoint">🔓 Задание 2: Обновление без подписи</a> - Обновите без проверки</li>
				<li><a href="/challenge/a08/3" class="api-endpoint">🔓 Задание 3: Данные без проверки целостности</a> - Сохраните без checksum</li>
				<li><a href="/challenge/a08/4" class="api-endpoint">🔓 Задание 4: Загрузка зависимостей без проверки</a> - Установите пакет без подписи</li>
				<li><a href="/challenge/a08/5" class="api-endpoint">🔓 Задание 5: Файлы без проверки checksum</a> - Загрузите без проверки</li>
				<li><a href="/challenge/a08/6" class="api-endpoint">🔓 Задание 6: CI/CD без проверки подписи</a> - Задеплойте без проверки</li>
				<li><a href="/challenge/a08/7" class="api-endpoint">🔓 Задание 7: Репозиторий без проверки</a> - Клонируйте без подписи коммитов</li>
				<li><a href="/challenge/a08/8" class="api-endpoint">🔓 Задание 8: Код без проверки подписи</a> - Выполните код без проверки</li>
				<li><a href="/challenge/a08/9" class="api-endpoint">🔓 Задание 9: Цепочка доверия не проверяется</a> - Проверьте сертификат</li>
				<li><a href="/challenge/a08/10" class="api-endpoint">🔓 Задание 10: Нет проверки времени модификации</a> - Проверьте файл</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A09: Security Logging and Alerting Failures (Ошибки логирования и оповещения)</h2>
			<ul>
				<li><a href="/challenge/a09/1" class="api-endpoint">🔓 Задание 1: Критические действия не логируются</a> - Удалите пользователя без лога</li>
				<li><a href="/challenge/a09/2" class="api-endpoint">🔓 Задание 2: Чувствительные данные в логах</a> - Найдите пароль в логах</li>
				<li><a href="/challenge/a09/3" class="api-endpoint">🔓 Задание 3: Мониторинг не настроен</a> - Проверьте статус мониторинга</li>
				<li><a href="/challenge/a09/4" class="api-endpoint">🔓 Задание 4: Недостаточное логирование</a> - Обработайте платеж</li>
				<li><a href="/challenge/a09/5" class="api-endpoint">🔓 Задание 5: Отсутствие алертов</a> - Выполните брутфорс без алерта</li>
				<li><a href="/challenge/a09/6" class="api-endpoint">🔓 Задание 6: Логи в открытом доступе</a> - Получите доступ к логам</li>
				<li><a href="/challenge/a09/7" class="api-endpoint">🔓 Задание 7: Отсутствие корреляции событий</a> - Получите список событий</li>
				<li><a href="/challenge/a09/8" class="api-endpoint">🔓 Задание 8: Недостаточная детализация</a> - Выполните действие</li>
				<li><a href="/challenge/a09/9" class="api-endpoint">🔓 Задание 9: Анализ логов не выполняется</a> - Проверьте анализ</li>
				<li><a href="/challenge/a09/10" class="api-endpoint">🔓 Задание 10: Логи хранятся небезопасно</a> - Проверьте хранилище</li>
			</ul>
		</div>
		
		<div class="card">
			<h2>A10: Mishandling of Exceptional Conditions (Неправильная обработка исключений)</h2>
			<ul>
				<li><a href="/challenge/a10/1" class="api-endpoint">🔓 Задание 1: Раскрытие информации в ошибках</a> - Получите stack trace</li>
				<li><a href="/challenge/a10/2" class="api-endpoint">🔓 Задание 2: Отсутствие обработки ошибок</a> - Выполните деление на ноль</li>
				<li><a href="/challenge/a10/3" class="api-endpoint">🔓 Задание 3: Чувствительные данные в логах</a> - Найдите пароль в ошибке</li>
				<li><a href="/challenge/a10/4" class="api-endpoint">🔓 Задание 4: Stack trace в ответе</a> - Получите полный stack trace</li>
				<li><a href="/challenge/a10/5" class="api-endpoint">🔓 Задание 5: Отсутствие валидации</a> - Переведите отрицательную сумму</li>
				<li><a href="/challenge/a10/6" class="api-endpoint">🔓 Задание 6: Неправильная обработка исключений</a> - Получите информацию о системе</li>
				<li><a href="/challenge/a10/7" class="api-endpoint">🔓 Задание 7: Race condition в обработке</a> - Отправьте одновременные запросы</li>
				<li><a href="/challenge/a10/8" class="api-endpoint">🔓 Задание 8: Утечка через таймауты</a> - Выполните timing attack</li>
				<li><a href="/challenge/a10/9" class="api-endpoint">🔓 Задание 9: Небезопасная обработка null</a> - Отправьте пустое значение</li>
				<li><a href="/challenge/a10/10" class="api-endpoint">🔓 Задание 10: Отсутствие graceful degradation</a> - Проверьте отказоустойчивость</li>
			</ul>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
