# BlockBoard

Пульт блокировки индикаторов компрометации (IOC) для домашней лаборатории безопасности.

Веб-интерфейс для блокировки IP-адресов и доменов на роутере **Keenetic** через RCI API:
каждый индикатор получает причину, срок жизни (TTL) и источник; по истечении TTL блокировка
снимается автоматически. Все действия уходят событиями в **Graylog** (GELF UDP).

## Возможности

- Блокировка IP — ACL файрвола `BlockBoard` на LAN-интерфейсе (Bridge0, направление in):
  deny-правила на каждый адрес + завершающий permit-all. ACL пересобирается из базы
  при каждом изменении (порядок правил критичен: deny должны идти раньше permit-all)
- Блокировка доменов — статическая DNS-запись `0.0.0.0` на роутере (имя перестаёт резолвиться)
- При старте сервис приводит роутер в соответствие со своей базой (self-healing)
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

## FeedPipe — автоблокировка из фидов IOC

`feedpipe.py` — конвейер «TrafficLens → BlockBoard»: читает базу IOC
TrafficLens (SQLite), отбирает IP/домены с confidence ≥ `FP_MIN_CONF`
(по умолчанию 80) и блокирует их через API BlockBoard с TTL
(`FP_TTL_HOURS`, по умолчанию 168 ч). Мёртвые C2 (Feodo «offline»),
приватные/служебные адреса и локальные домены пропускаются.
Дедупликация — на стороне BlockBoard, поэтому скрипт идемпотентен;
за один прогон добавляется не более `FP_MAX_PER_RUN` (50) блокировок.

Запуск по таймеру (`~/.config/systemd/user/feedpipe.{service,timer}`,
каждый час в :17), учётка и параметры — в `~/blockboard/feedpipe.env`.
Проверка без изменений: `FP_DRY=1 python3 feedpipe.py`.
