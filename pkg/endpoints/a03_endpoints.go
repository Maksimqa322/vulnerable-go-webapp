package endpoints

import (
	"fmt"
	"net/http"
	"os/exec"
)

// A03:2025 - Software Supply Chain Failures
// 10 реалистичных эндпоинтов

// Уязвимость 1: Установка пакетов без проверки
func apiV1PackagesInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		packageName := r.FormValue("package")
		
		// УЯЗВИМОСТЬ: Устанавливаем пакет без проверки подписи и целостности
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Package %s installed without signature verification", packageName),
			"version": "latest",
		})
		return
	}
	
	html := renderPage("Install Package", `
		<div class="card">
			<h2>Install NPM Package</h2>
			<form method="POST">
				<div class="form-group">
					<label>Package Name</label>
					<input type="text" name="package" value="lodash" placeholder="package-name">
				</div>
				<button type="submit" class="btn">Install</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 2: Загрузка зависимостей из небезопасных источников
func apiV1DependenciesUpdate(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	
	// УЯЗВИМОСТЬ: Загружаем зависимости с любого URL
	if url != "" {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Dependency loaded from %s without verification", url),
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "URL parameter required",
		})
	}
}

// Уязвимость 3: Выполнение произвольного кода через npm scripts
func apiV1Build(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		script := r.FormValue("script")
		
		// УЯЗВИМОСТЬ: Выполняем произвольную команду
		out, _ := exec.Command("sh", "-c", script).Output()
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"output":  string(out),
		})
		return
	}
	
	html := renderPage("Build Project", `
		<div class="card">
			<h2>Run Build Script</h2>
			<form method="POST">
				<div class="form-group">
					<label>Build Script</label>
					<input type="text" name="script" value="npm run build" placeholder="command">
				</div>
				<button type="submit" class="btn">Run</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 4: Отсутствие проверки checksum при обновлении
func apiV1Update(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("version")
	
	// УЯЗВИМОСТЬ: Обновление без проверки checksum
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Updated to version %s without checksum verification", version),
		"warning": "File integrity not verified",
	})
}

// Уязвимость 5: Использование устаревших библиотек с известными уязвимостями
func apiV1DependenciesList(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Используем устаревшие библиотеки
	sendJSON(w, map[string]interface{}{
		"dependencies": map[string]string{
			"express":           "4.16.0", // CVE-2022-24999
			"lodash":            "4.17.11", // CVE-2021-23337
			"axios":             "0.19.0", // CVE-2021-3749
			"jsonwebtoken":      "8.5.0",  // CVE-2022-23539
			"moment":            "2.24.0", // CVE-2022-24785
		},
		"vulnerabilities": "15 known CVEs",
	})
}

// Уязвимость 6: Typosquatting - установка похожих пакетов
func apiV1PackagesSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	// УЯЗВИМОСТЬ: Принимаем похожие имена пакетов
	if query == "express" || query == "expres" || query == "expresss" {
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"package": query,
			"message": fmt.Sprintf("Package '%s' found and installed (possible typosquatting!)", query),
		})
	} else {
		sendJSON(w, map[string]interface{}{
			"status":  "error",
			"message": "Package not found",
		})
	}
}

// Уязвимость 7: Компрометированный репозиторий
func apiV1RepoClone(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	
	// УЯЗВИМОСТЬ: Клонируем репозиторий без проверки подписи коммитов
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Repository %s cloned without commit signature verification", repo),
		"warning": "If repository is compromised, malicious code may be executed",
	})
}

// Уязвимость 8: Небезопасное обновление через webhook
func apiV1WebhookUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// УЯЗВИМОСТЬ: Обновляем код из webhook без проверки подписи
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": "Code updated from webhook without signature verification",
		})
		return
	}
	
	sendJSON(w, map[string]interface{}{
		"status":  "error",
		"message": "POST required",
	})
}

// Уязвимость 9: Подмена зависимостей через DNS
func apiV1PackageRegistry(w http.ResponseWriter, r *http.Request) {
	packageName := r.URL.Query().Get("package")
	
	// УЯЗВИМОСТЬ: Загружаем пакет без проверки DNS и репозитория
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"package": packageName,
		"registry": "https://registry.npmjs.org (DNS not verified)",
		"warning": "Package may be loaded from compromised DNS",
	})
}

// Уязвимость 10: Транзитивные зависимости с уязвимостями
func apiV1DependenciesTree(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Показываем дерево зависимостей с уязвимостями
	w.Write([]byte(`my-app@1.0.0
├── express@4.16.0 (CVE-2022-24999)
│   └── body-parser@1.18.3 (CVE-2020-19719)
│       └── debug@2.6.9 (CVE-2017-16137)
├── lodash@4.17.11 (CVE-2021-23337)
└── axios@0.19.0 (CVE-2021-3749)
    └── follow-redirects@1.5.10 (CVE-2022-0155)

Total: 15 known vulnerabilities
No automated security scanning enabled`))
}

