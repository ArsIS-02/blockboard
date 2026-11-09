# BlockBoard

Пульт блокировки индикаторов компрометации (IOC) для домашней лаборатории безопасности.

Веб-интерфейс для блокировки IP-адресов и доменов на роутере **Keenetic** через RCI API:
каждый индикатор получает причину, срок жизни (TTL) и источник; по истечении TTL блокировка
снимается автоматически. Все действия уходят событиями в **Graylog** (GELF UDP).

## Возможности

- Блокировка IP (reject-маршрут на Keenetic) и доменов (статическая DNS-запись `0.0.0.0`)
- TTL: 1 час / 24 часа / 3 суток / неделя / бессрочно, авто-снятие по таймеру
- Режим **dry-run**: действия только журналируются, пока роутер не подключён
- Журнал действий, продление блокировок, ручное снятие
- Глубокая ссылка `/?block=<IP>&reason=<текст>` — для кнопок «Заблокировать» в письмах Graylog и других инструментах
- Авторизация (сессии), светлая/тёмная тема
- Только стандартная библиотека Python — никаких зависимостей

## Запуск (Podman)

```bash
podman build -t localhost/blockboard:latest -f Containerfile .
```

Quadlet-юнит `~/.config/containers/systemd/blockboard.container`:

```ini
[Unit]
Description=BlockBoard — пульт блокировки IOC
After=network-online.target

[Container]
Image=localhost/blockboard:latest
PublishPort=8098:8098
Volume=/home/redos/blockboard/data:/data:Z
EnvironmentFile=/home/redos/blockboard/blockboard.env

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
```

`blockboard.env`:

```
BB_USER=admin
BB_PASS=admin          # поменяйте!
GELF_HOST=host.containers.internal
GELF_PORT=12206
```

## Настройка Keenetic

Веб-интерфейс → ⚙ Настройки: адрес роутера, логин и пароль администратора,
кнопка «Проверить связь» выполняет `show version` через RCI.
Пароль хранится только в локальной SQLite-базе сервиса (`/data/blockboard.db`).

## API

| Метод | Путь | Описание |
|---|---|---|
| POST | `/api/login` | вход `{user, password}` |
| GET | `/api/blocks` | активные блокировки |
| POST | `/api/blocks` | новая `{indicator, reason, source, ttl_hours}` |
| POST | `/api/blocks/<id>/unblock` | снять блокировку |
| POST | `/api/blocks/<id>/extend` | продлить `{hours}` |
| GET | `/api/history` | журнал |
| GET/POST | `/api/settings` | настройки роутера |
| POST | `/api/test-router` | проверка связи с Keenetic |

## События в Graylog

GELF UDP, поля: `tool=blockboard`, `action=block|unblock|expire`,
`indicator`, `itype`, `reason`, `result`, `ttl_hours`.
