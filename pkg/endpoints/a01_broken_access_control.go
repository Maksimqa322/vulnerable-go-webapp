package endpoints

import (
	"fmt"
	"net/http"
	"strconv"
)

// A01:2025 - Broken Access Control
// 10 уязвимостей разной сложности

func a01BrokenAccessControl(w http.ResponseWriter, r *http.Request) {
	html := `
	<h1>A01: Broken Access Control</h1>
	<h2>Уязвимость 1 (Легкая): Прямой доступ к файлам</h2>
	<a href="/admin/secret.txt">Скачать секретный файл</a>
	
	<h2>Уязвимость 2 (Легкая): IDOR - изменение чужого ID</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="2">
		User ID: <input type="text" name="user_id" value="1">
		<button>Показать профиль</button>
	</form>
	
	<h2>Уязвимость 3 (Легкая): Отсутствие проверки роли</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="3">
		Role: <input type="text" name="role" value="user">
		<button>Получить доступ</button>
	</form>
	
	<h2>Уязвимость 4 (Средняя): Слабая проверка токена</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="4">
		Token: <input type="text" name="token" value="admin123">
		<button>Проверить токен</button>
	</form>
	
	<h2>Уязвимость 5 (Средняя): Обход через параметр</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="5">
		Admin: <input type="text" name="is_admin" value="false">
		<button>Проверить</button>
	</form>
	
	<h2>Уязвимость 6 (Средняя): Небезопасная редирект</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="6">
		Redirect: <input type="text" name="redirect" value="/admin">
		<button>Перейти</button>
	</form>
	
	<h2>Уязвимость 7 (Сложная): JWT без проверки подписи</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="7">
		JWT: <input type="text" name="jwt" value="eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.">
		<button>Проверить JWT</button>
	</form>
	
	<h2>Уязвимость 8 (Сложная): Race condition</h2>
	<form method="POST" action="/a01">
		<input type="hidden" name="vuln" value="8">
		Action: <input type="text" name="action" value="transfer">
		Amount: <input type="text" name="amount" value="1000">
		<button>Выполнить</button>
	</form>
	
	<h2>Уязвимость 9 (Сложная): Обход через заголовки</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="9">
		<button>Проверить заголовки</button>
	</form>
	
	<h2>Уязвимость 10 (Сложная): CORS misconfiguration</h2>
	<form method="GET" action="/a01">
		<input type="hidden" name="vuln" value="10">
		Origin: <input type="text" name="origin" value="evil.com">
		<button>Проверить CORS</button>
	</form>
	`

	vuln := r.URL.Query().Get("vuln")

	// Уязвимость 1: Прямой доступ к файлам
	if vuln == "1" || r.URL.Path == "/admin/secret.txt" {
		w.Write([]byte("SECRET_KEY=12345\nADMIN_PASSWORD=admin"))
		return
	}

	// Уязвимость 2: IDOR - нет проверки принадлежности
	if vuln == "2" {
		userID := r.URL.Query().Get("user_id")
		w.Write([]byte(fmt.Sprintf("Профиль пользователя %s: Email=user%s@test.com, Balance=10000", userID, userID)))
		return
	}

	// Уязвимость 3: Отсутствие проверки роли
	if vuln == "3" {
		role := r.URL.Query().Get("role")
		if role == "admin" {
			w.Write([]byte("Доступ к админ панели разрешен!"))
		} else {
			w.Write([]byte("Обычный пользователь"))
		}
		return
	}

	// Уязвимость 4: Слабая проверка токена
	if vuln == "4" {
		token := r.URL.Query().Get("token")
		if token == "admin123" || token == "admin" || len(token) > 5 {
			w.Write([]byte("Доступ разрешен! Админ панель: /admin"))
		} else {
			w.Write([]byte("Доступ запрещен"))
		}
		return
	}

	// Уязвимость 5: Обход через параметр
	if vuln == "5" {
		isAdmin := r.URL.Query().Get("is_admin")
		if isAdmin == "true" || isAdmin == "1" || isAdmin == "True" || isAdmin == "TRUE" {
			w.Write([]byte("Админ доступ получен!"))
		} else {
			w.Write([]byte("Обычный доступ"))
		}
		return
	}

	// Уязвимость 6: Небезопасная редирект
	if vuln == "6" {
		redirect := r.URL.Query().Get("redirect")
		http.Redirect(w, r, redirect, 302)
		return
	}

	// Уязвимость 7: JWT без проверки подписи
	if vuln == "7" {
		jwt := r.URL.Query().Get("jwt")
		// Нет проверки подписи, просто декодируем
		if len(jwt) > 10 {
			w.Write([]byte("JWT принят! Пользователь: admin"))
		}
		return
	}

	// Уязвимость 8: Race condition (упрощенная демонстрация)
	if vuln == "8" && r.Method == "POST" {
		amount, _ := strconv.Atoi(r.FormValue("amount"))
		// Нет блокировки, можно отправить несколько запросов одновременно
		w.Write([]byte(fmt.Sprintf("Перевод %d выполнен", amount)))
		return
	}

	// Уязвимость 9: Обход через заголовки
	if vuln == "9" {
		// Проверяем заголовок, но можно подделать
		if r.Header.Get("X-Admin") == "true" || r.Header.Get("X-Forwarded-User") == "admin" {
			w.Write([]byte("Админ доступ через заголовки!"))
		} else {
			w.Write([]byte("Обычный доступ"))
		}
		return
	}

	// Уязвимость 10: CORS misconfiguration
	if vuln == "10" {
		origin := r.URL.Query().Get("origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte("CORS настроен для: " + origin))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
