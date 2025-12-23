#!/bin/bash
# Скрипт для остановки сервера

echo "Остановка сервера..."

# Найти и остановить процессы Go
pkill -f "go run main.go" 2>/dev/null
pkill -f "/tmp/go-build.*/exe/main" 2>/dev/null

# Найти процесс на порту 9999 и остановить его
PORT_PID=$(lsof -ti:9999 2>/dev/null)
if [ ! -z "$PORT_PID" ]; then
    echo "Остановка процесса на порту 9999 (PID: $PORT_PID)"
    kill $PORT_PID 2>/dev/null
    sleep 1
    # Если процесс не остановился, принудительно
    kill -9 $PORT_PID 2>/dev/null
fi

sleep 1

# Проверить, что порт свободен
if lsof -ti:9999 >/dev/null 2>&1; then
    echo "⚠️  Порт 9999 все еще занят. Попробуйте: kill -9 \$(lsof -ti:9999)"
else
    echo "✅ Сервер успешно остановлен"
fi

