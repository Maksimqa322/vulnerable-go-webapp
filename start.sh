#!/bin/bash
# Скрипт для запуска сервера

echo "Запуск сервера..."

# Проверить, не занят ли порт
if lsof -ti:9999 >/dev/null 2>&1; then
    echo "⚠️  Порт 9999 уже занят!"
    echo "Остановите текущий сервер: ./stop.sh"
    exit 1
fi

cd "$(dirname "$0")/cmd" || exit 1

echo "Сервер запускается на http://localhost:9999"
echo "Для остановки нажмите Ctrl+C или выполните: ./stop.sh"
echo ""

go run main.go