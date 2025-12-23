package endpoints

import (
	"fmt"
	"net/http"
)

// Общие стили для всех страниц (имитация реального приложения)
const commonStyles = `
<style>
	* { margin: 0; padding: 0; box-sizing: border-box; }
	body {
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
		background: #f8f9fa;
		color: #212529;
		line-height: 1.6;
	}
	.container {
		max-width: 1200px;
		margin: 0 auto;
		padding: 20px;
	}
	.header {
		background: #fff;
		border-bottom: 1px solid #dee2e6;
		padding: 15px 0;
		margin-bottom: 30px;
	}
	.header h1 {
		font-size: 24px;
		color: #495057;
		margin-bottom: 5px;
	}
	.header .subtitle {
		color: #6c757d;
		font-size: 14px;
	}
	.card {
		background: #fff;
		border: 1px solid #dee2e6;
		border-radius: 6px;
		padding: 24px;
		margin-bottom: 20px;
		box-shadow: 0 1px 3px rgba(0,0,0,0.1);
	}
	.card h2 {
		font-size: 20px;
		margin-bottom: 16px;
		color: #212529;
		border-bottom: 2px solid #007bff;
		padding-bottom: 8px;
	}
	.form-group {
		margin-bottom: 16px;
	}
	.form-group label {
		display: block;
		margin-bottom: 6px;
		font-weight: 500;
		color: #495057;
		font-size: 14px;
	}
	.form-group input,
	.form-group textarea,
	.form-group select {
		width: 100%;
		padding: 10px 12px;
		border: 1px solid #ced4da;
		border-radius: 4px;
		font-size: 14px;
		font-family: inherit;
	}
	.form-group input:focus,
	.form-group textarea:focus {
		outline: none;
		border-color: #007bff;
		box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
	}
	.btn {
		display: inline-block;
		padding: 10px 20px;
		background: #007bff;
		color: #fff;
		border: none;
		border-radius: 4px;
		font-size: 14px;
		font-weight: 500;
		cursor: pointer;
		text-decoration: none;
	}
	.btn:hover {
		background: #0056b3;
	}
	.btn-danger {
		background: #dc3545;
	}
	.btn-danger:hover {
		background: #c82333;
	}
	.response {
		background: #f8f9fa;
		border: 1px solid #dee2e6;
		border-radius: 4px;
		padding: 16px;
		margin-top: 20px;
		font-family: 'Courier New', monospace;
		font-size: 13px;
		white-space: pre-wrap;
		word-wrap: break-word;
	}
	.response.success {
		background: #d4edda;
		border-color: #c3e6cb;
		color: #155724;
		font-size: 16px;
		padding: 20px;
	}
	.response.error {
		background: #f8d7da;
		border-color: #f5c6cb;
		color: #721c24;
	}
	.checkmark {
		font-size: 24px;
		color: #28a745;
		margin-right: 10px;
	}
	.api-endpoint {
		background: #e9ecef;
		padding: 4px 8px;
		border-radius: 3px;
		font-family: 'Courier New', monospace;
		font-size: 13px;
		color: #495057;
	}
	.badge {
		display: inline-block;
		padding: 4px 8px;
		border-radius: 3px;
		font-size: 12px;
		font-weight: 500;
	}
	.badge-danger {
		background: #dc3545;
		color: #fff;
	}
	.badge-warning {
		background: #ffc107;
		color: #000;
	}
	.badge-info {
		background: #17a2b8;
		color: #fff;
	}
	.nav {
		background: #fff;
		border-bottom: 1px solid #dee2e6;
		padding: 10px 0;
		margin-bottom: 20px;
	}
	.nav a {
		color: #007bff;
		text-decoration: none;
		margin-right: 20px;
		font-size: 14px;
	}
	.nav a:hover {
		text-decoration: underline;
	}
</style>
`

// Функция для создания базового HTML шаблона
func renderPage(title, content string) string {
	return `<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + title + `</title>
	` + commonStyles + `
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>` + title + `</h1>
			<div class="subtitle">API Endpoint</div>
		</div>
		<div class="nav">
			<a href="/">Главная</a>
			<a href="/explanations">Объяснения уязвимостей</a>
		</div>
		` + content + `
	</div>
</body>
</html>`
}

// Функция для отправки JSON ответа (упрощенная версия)
func sendJSON(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json := "{\n"
	first := true
	for k, v := range data {
		if !first {
			json += ",\n"
		}
		first = false
		json += `  "` + k + `": `
		switch val := v.(type) {
		case string:
			json += `"` + val + `"`
		case int:
			json += fmt.Sprintf("%d", val)
		case []map[string]string:
			json += "["
			for i, item := range val {
				if i > 0 {
					json += ", "
				}
				json += "{"
				firstItem := true
				for k2, v2 := range item {
					if !firstItem {
						json += ", "
					}
					firstItem = false
					json += `"` + k2 + `": "` + v2 + `"`
				}
				json += "}"
			}
			json += "]"
		case map[string]string:
			json += "{"
			firstItem := true
			for k2, v2 := range val {
				if !firstItem {
					json += ", "
				}
				firstItem = false
				json += `"` + k2 + `": "` + v2 + `"`
			}
			json += "}"
		default:
			json += `"` + fmt.Sprintf("%v", val) + `"`
		}
	}
	json += "\n}"
	w.Write([]byte(json))
}

