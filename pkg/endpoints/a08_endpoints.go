package endpoints

import (
	"fmt"
	"net/http"
)

// A08:2025 - Software or Data Integrity Failures
// 10 реалистичных эндпоинтов

// Уязвимость 1: Загрузка файлов без проверки подписи
func apiV1UpdateUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		file := r.FormValue("file")
		
		// УЯЗВИМОСТЬ: Файл загружается без проверки цифровой подписи
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("File %s uploaded without signature verification", file),
			"warning": "Malicious code may be executed",
		})
		return
	}
	
	html := renderPage("Upload Update", `
		<div class="card">
			<h2>Upload Update File</h2>
			<form method="POST">
				<div class="form-group">
					<label>File Name</label>
					<input type="text" name="file" value="update.zip">
				</div>
				<button type="submit" class="btn">Upload</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 2: Обновление без проверки подписи
func apiV1UpdateInstall(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("version")
	
	// УЯЗВИМОСТЬ: Обновление выполняется без проверки подписи разработчика
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Updated to version %s without signature verification", version),
		"warning": "Compromised update may be installed",
	})
}

// Уязвимость 3: Данные без проверки целостности
func apiV1DataSave(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		data := r.FormValue("data")
		
		// УЯЗВИМОСТЬ: Данные сохраняются без checksum
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Data saved without integrity check: %s", data),
			"warning": "Data may be modified without detection",
		})
		return
	}
	
	html := renderPage("Save Data", `
		<div class="card">
			<h2>Save Data</h2>
			<form method="POST">
				<div class="form-group">
					<label>Data</label>
					<textarea name="data">important data</textarea>
				</div>
				<button type="submit" class="btn">Save</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 4: Загрузка зависимостей без проверки
func apiV1DependenciesInstall(w http.ResponseWriter, r *http.Request) {
	packageName := r.URL.Query().Get("package")
	
	// УЯЗВИМОСТЬ: Пакет устанавливается без проверки подписи
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Package %s installed without signature verification", packageName),
		"warning": "Compromised package may be installed",
	})
}

// Уязвимость 5: Файлы без проверки checksum
func apiV1FilesUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		file := r.FormValue("file")
		
		// УЯЗВИМОСТЬ: Файл загружается без проверки SHA256/MD5
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("File %s uploaded without checksum verification", file),
			"warning": "File integrity not verified",
		})
		return
	}
	
	html := renderPage("Upload File", `
		<div class="card">
			<h2>Upload File</h2>
			<form method="POST">
				<div class="form-group">
					<label>File Name</label>
					<input type="text" name="file" value="app.zip">
				</div>
				<button type="submit" class="btn">Upload</button>
			</form>
		</div>
	`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Уязвимость 6: CI/CD без проверки подписи
func apiV1CICDDeploy(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: CI/CD pipeline не проверяет подпись кода
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": "Code deployed via CI/CD without signature verification",
		"warning": "Compromised code may be deployed",
	})
}

// Уязвимость 7: Репозиторий без проверки подписи коммитов
func apiV1RepoPull(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	
	// УЯЗВИМОСТЬ: Репозиторий клонируется без проверки подписи
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Repository %s pulled without commit signature verification", repo),
		"warning": "Compromised commits may be executed",
	})
}

// Уязвимость 8: Код выполняется без проверки подписи
func apiV1CodeExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		code := r.FormValue("code")
		
		// УЯЗВИМОСТЬ: Код выполняется без проверки цифровой подписи
		sendJSON(w, map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Code executed without signature verification: %s", code),
			"warning": "Malicious code may be executed",
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

// Уязвимость 9: Цепочка доверия не проверяется
func apiV1CertificateVerify(w http.ResponseWriter, r *http.Request) {
	// УЯЗВИМОСТЬ: Сертификаты не проверяются
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"message": "Certificate chain not verified",
		"warning": "Fake certificates may be accepted",
	})
}

// Уязвимость 10: Нет проверки времени модификации
func apiV1FileCheck(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	
	// УЯЗВИМОСТЬ: Нет проверки времени модификации файла
	sendJSON(w, map[string]interface{}{
		"status":  "success",
		"file":    file,
		"message": fmt.Sprintf("File %s checked without timestamp verification", file),
		"warning": "File may be rolled back to previous version",
	})
}

