# Guardian: настройка и эксплуатация

Конфигурация, запуск, API и метрики Guardian. Адреса в примерах соответствуют настройкам по умолчанию.

Связанные материалы:

| Документ | Содержание |
|----------|------------|
| [README.md](../README.md) | Быстрый старт |
| [about.md](./about.md) | Цели и задачи разработки (введение) |
| [test-result.md](./test-result.md) | Нагрузочный тест (hey) и разбор результатов |
| [architecture.md](./architecture.md) | Потоки данных и оптимизации |
| [c4.md](./c4.md) | C4-модель |
| [admin-guide.md](./admin-guide.md) | Роли, правила, trusted proxies |
| [openapi.yaml](./openapi.yaml) | Спецификация Admin API |
| [task.md](../doc/task.md) | Исходное ТЗ |

---

## 1. Назначение сервиса

**Guardian** - HTTP-прокси с поддержкой HTTPS через CONNECT на Go (`fasthttp`) с:

- фильтрацией трафика по правилам (Filter Engine);
- RBAC и JWT (локальный HS256 либо внешний OAuth2/IdP);
- защитой от SSRF (блокировка private/loopback/link-local/CGNAT/metadata);
- rate limit и лимитом соединений на IP;
- Admin REST API для правил, пользователей и статистики;
- метриками Prometheus;
- опциональной публикацией событий в Kafka.

Guardian управляет исходящими запросами приложений. Правила хранятся в PostgreSQL и обновляются без перезапуска. Управление доступно через Admin API; встроенного интерфейса администратора, PAC/WPAD и функций WAF нет. Кэш HTTP-ответов выключен по умолчанию.

### Порты

| Порт | Назначение |
|------|------------|
| **8080** | Прокси (клиенты: `curl -x`, системный HTTP proxy) |
| **8081** | Admin API, `/health`, `/ready` |
| **9090** | Prometheus `/metrics`, `/health` |

### Путь обработки прокси-запроса

1. Лимит соединений на IP (`ConnTracker`)
2. Лимит размера тела
3. Rate limit по IP, если `rate_limit.enabled: true`
4. Проверка токена (обязателен при `require_auth_for_proxy: true`), затем пользовательской квоты и права `proxy:access`
5. Filter Engine: первое совпавшее правило по убыванию приоритета; `block` сразу завершает обработку
6. Для HTTP - изменение заголовков по `modify`, затем поиск подходящего ответа в кэше
7. При отсутствии ответа из кэша - SSRF-проверка и Forward HTTP или открытие CONNECT-туннеля
8. Для HTTP - сохранение подходящего ответа в кэш и замена тела по `modify`

HTTPS передаётся без расшифровки TLS. Правила и RPS применяются к запросу CONNECT; пути, заголовки, тела и отдельные HTTPS-запросы внутри туннеля не анализируются. Действие `modify` для CONNECT не применяется.


---

## 2. Конфигурация

### 2.1. Как загружается конфиг

1. Файл (по умолчанию `configs/config.yaml`, флаг `-config`).
2. Переменные окружения с префиксом **`GUARDIAN_`**.

Имя переменной окружения получается из полного ключа YAML: точки заменяются на `_`, буквы переводятся в верхний регистр, добавляется префикс `GUARDIAN_`.

| YAML | Env |
|------|-----|
| `auth.jwt_secret` | `GUARDIAN_AUTH_JWT_SECRET` |
| `server.proxy_addr` | `GUARDIAN_SERVER_PROXY_ADDR` |
| `proxy.allow_private_targets` | `GUARDIAN_PROXY_ALLOW_PRIVATE_TARGETS` |

Непустая переменная окружения имеет приоритет над файлом. Пустые переменные окружения Viper не учитывает: чтобы отключить bootstrap, задайте пустое значение в YAML и уберите непустое переопределение. Для загрузки через `Unmarshal` ключ должен присутствовать в YAML либо наборе значений по умолчанию; используйте полный `configs/config.yaml`, особенно для OAuth2 URL и read replica. Списки CIDR в переменных окружения разделяются запятыми.

Пример локальных переменных: `configs/config.local.env.example`.

Ошибки чтения файла конфигурации сейчас игнорируются загрузчиком: при отсутствии или ошибке чтения используются доступные значения по умолчанию и переменные окружения. Ошибка чтения не прерывает запуск, поэтому неверный путь может остаться незамеченным.

### 2.2. Справочник ключей

Ниже указаны значения по умолчанию из кода; файл конфигурации и переменные окружения могут их переопределять.

#### `server` - HTTP-серверы Guardian

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `proxy_addr` | string | `:8080` | Адрес прокси |
| `admin_addr` | string | `:8081` | Admin API + health/ready |
| `metrics_addr` | string | `:9090` | Prometheus + `/health` |
| `read_timeout` | duration | `30s` | Таймаут чтения |
| `write_timeout` | duration | `30s` | Таймаут записи |
| `idle_timeout` | duration | `60s` | Idle keep-alive (прокси) |
| `max_conns` | int | `10000` | Concurrency fasthttp (прокси) |
| `max_request_body` | int | `10485760` | Макс. тело запроса (байты) |
| `shutdown_timeout` | duration | `30s` | Graceful shutdown |
| `trusted_proxies` | []string | `[]` | CIDR (или IP), от которых доверяются `X-Forwarded-For` / `X-Real-IP` |

#### `proxy` - исходящий клиент к upstream

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `max_conns_per_host` | int | `1000` | Пул соединений на хост |
| `read_timeout` | duration | `30s` | Чтение ответа upstream |
| `write_timeout` | duration | `30s` | Запись в upstream |
| `dial_timeout` | duration | `5s` | Dial (CONNECT) |
| `max_idle_conn_duration` | duration | `30s` | Idle в пуле |
| `dns_cache_ttl` | duration | `1h` | DNS cache dialer |
| `dial_concurrency` | int | `4096` | Параллелизм dial |
| `buffer_size` | int | `32768` | Буфер копирования туннеля |
| `allow_private_targets` | bool | `false` | Разрешить частные и локальные цели (в рабочем окружении оставьте `false`) |

#### `postgres`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `dsn` | string | local DSN | Основная БД |
| `max_conns` | int32 | `50` | Макс. соединений пула |
| `min_conns` | int32 | `5` | Мин. соединений |
| `max_conn_lifetime` | duration | `1h` | Время жизни соединения |
| `max_conn_idle_time` | duration | `30m` | Idle в пуле |
| `read_replica_dsn` | string | `""` | Опциональная read-replica |

#### `redis`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `enabled` | bool | `true` | Использовать Redis; иначе только память |
| `addr` | string | `localhost:6379` | Адрес |
| `password` | string | `""` | Пароль |
| `db` | int | `0` | Номер БД |
| `pool_size` | int | `100` | Размер пула |

При недоступности Redis на старте сервис пишет warning и переключается на in-memory кэш.

#### `auth`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `jwt_secret` | string | `""` | Секрет HS256 (≥16, не дефолтный); обязателен при локальном JWT/bootstrap |
| `jwt_issuer` | string | `guardian` | Issuer выдаваемого локального JWT; проверка `iss` внешнего JWT в JWKS-режиме |
| `token_cache_ttl` | duration | `10m` | TTL кэша проверенных токенов |
| `oauth2_enabled` | bool | `false` | Включить внешний валидатор |
| `oauth2_introspect_url` | string | `""` | RFC 7662 introspection (opaque) |
| `oauth2_jwks_url` | string | `""` | JWKS для RSA JWT (приоритетнее introspection) |
| `require_auth_for_proxy` | bool | `false` | Требовать токен на `:8080` (локальный либо внешний режим) |
| `bootstrap_token` | string | `""` | **Только dev:** включает `POST /api/v1/auth/token` |

#### `cache`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `enabled` | bool | `true` | Вместе с `response_enabled` включает кэш HTTP-ответов; не отключает кэш токенов и обновление правил |
| `rules_ttl` | duration | `30s` | TTL кэша правил + период reload |
| `response_ttl` | duration | `60s` | TTL response cache |
| `response_enabled` | bool | `false` | Включить кэш подходящих HTTP-ответов совместно с `cache.enabled` |

Response cache (если включён): только анонимные GET без `Cookie`/`Authorization`, ответ `200` с `Cache-Control: public`, без `Set-Cookie`, `Vary` и директив `private`/`no-store`/`no-cache`. TTL задаётся `response_ttl`, а не `max-age` upstream. Тело сохраняется до применения `modify`; при попадании в кэш замена тела по правилу не выполняется.

#### `queue`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `enabled` | bool | `false` | Публикация событий |
| `backend` | string | `none` | `kafka` или `none` |
| `brokers` | string | `localhost:9092` | Список брокеров через запятую |
| `topic` | string | `guardian-events` | Топик |
| `group_id` | string | `guardian` | Используется как **Kafka client ID** (не consumer group) |

#### `rate_limit`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `enabled` | bool | `true` | Включить RPS-лимиты; не отключает `max_conns_per_ip` |
| `default_rps` | int | `1000` | RPS по умолчанию (и fallback квоты) |
| `burst` | int | `2000` | Ёмкость локального token bucket (не меньше RPS); при Redis не применяется |
| `per_ip_limit` | int | `500` | RPS на IP |
| `max_conns_per_ip` | int | `100` | Одновременные вызовы обработчика на IP; открытые CONNECT-туннели после hijack не учитываются |

#### `log`

| Ключ | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `level` | string | `info` | Уровень zap |
| `format` | string | `json` | `json` или `console` |
| `persist_requests` | bool | `false` | Асинхронная запись `request_logs` в PostgreSQL; создаёт дополнительную нагрузку на БД |

---

## 3. Проверка токенов, правила и ограничения

### Аутентификация

- **Прокси (`:8080`)** по умолчанию **анонимный**. Внешняя проверка вызывается при переданном `Authorization`, включённом `oauth2_enabled` и промахе кэша. При обязательной аутентификации отсутствие заголовка сразу даёт `401`.
- **Admin API (`:8081`)** требует токен выбранного режима. Исключения: `/health`, `/ready` и выдача токена по bootstrap-секрету.
- Локальный JWT: HS256 + `jwt_secret`.
- Внешний: JWKS (RSA) или introspection -> `TokenClaims` (`user_id`/`sub`, `email`, `role`, `active`, `quota_rps`).
- Bootstrap (`bootstrap_token`) предназначен для разработки и начальной настройки; в рабочем окружении отключить. Автоматического отключения по среде запуска нет.

### OAuth2 / внешний IdP

Guardian проверяет токены внешнего IdP. Клиент получает их у IdP самостоятельно: формы входа и Authorization Code Flow в Guardian нет.

#### Как включить

```yaml
auth:
  oauth2_enabled: true
  oauth2_jwks_url: "https://idp.example.com/.well-known/jwks.json"   # предпочтительно для JWT
  # или:
  # oauth2_introspect_url: "https://idp.example.com/oauth/introspect"
  jwt_issuer: "https://idp.example.com/" # точное значение iss вашего IdP (JWKS-режим)
  require_auth_for_proxy: true   # если прокси тоже должен требовать токен IdP
  bootstrap_token: ""            # в рабочем окружении отключить
```

Env-эквиваленты: `GUARDIAN_AUTH_OAUTH2_ENABLED`, `GUARDIAN_AUTH_OAUTH2_JWKS_URL`, `GUARDIAN_AUTH_OAUTH2_INTROSPECT_URL`.

Режимы проверки (если заданы оба URL, используется **JWKS**):

| Режим | Когда | Поведение |
|-------|--------|-----------|
| **JWKS** | RSA JWT с `kid` | Загрузка ключей с IdP (кэш ~5 мин), проверка подписи и опционально `iss` |
| **Introspection** | Opaque-токен | `POST` form-urlencoded `token=...` на IdP; нужен `active: true` |

Claims -> `TokenClaims`: `user_id` или `sub` (UUID), `email`, `role` либо массив `roles`, `active`, `quota_rps`. Без валидного UUID или распознанной роли токен отклоняется. Из массива `roles` выбирается наиболее привилегированная известная роль. Для JWKS отсутствие `active` трактуется как `true`; introspection требует явного `active: true`. При ответе introspection `400` или `415` запрос повторяется в JSON-формате. Аутентификация клиента на introspection endpoint в текущей реализации не настроена.

При `oauth2_enabled: true` внешний валидатор подключается в `ValidateToken`: после промаха кэша токены идут в IdP/JWKS, **локальный HS256 не используется**. Локальная подпись bootstrap-JWT в этом режиме не проверяется; используйте токен IdP.

#### Где проверяется токен

Guardian проверяет `Authorization: Bearer ...` в следующих обработчиках:

| Где | Условие проверки токена |
|-----|-----------------------------------------------|
| **Прокси `:8080`** | Есть заголовок `Authorization`, либо `require_auth_for_proxy: true` (без заголовка сразу `401`) |
| **Admin** `POST /api/v1/auth/logout` | Валидация текущего Bearer |
| **Admin** все защищённые `/api/v1/rules*`, `/api/v1/users*`, `/api/v1/stats*` | Через `requirePerm` -> `ValidateToken` |
| **Не вызывается** | `GET /health`, `GET /ready` на admin-порту, `POST /api/v1/auth/token` (только bootstrap), анонимный прокси без `Authorization` при `require_auth_for_proxy: false` |
| **Метрики `:9090`** | `/metrics`, `/health` - без auth |

Успешный результат кэшируется (`token_cache_ttl`, по умолчанию 10m). До истечения TTL повторная проверка срока действия и статуса токена у IdP не выполняется: TTL кэша не ограничивается полем `exp`, поэтому истёкший JWT может приниматься до истечения TTL кэшированного результата. Это ограничение реализации проверки токенов в Guardian. Ротация ключей JWKS сама по себе не отзывает уже кэшированные результаты проверки.

При включённом внешнем валидаторе нужно задать хотя бы один URL проверки; иначе сервис не запустится. Экземплярам Guardian необходим сетевой доступ к JWKS или introspection. При недоступности IdP новая проверка может завершиться ошибкой; уже кэшированные результаты используются до истечения TTL.

### Пользовательская квота

`quota_rps` берётся из проверенного токена и применяется при `rate_limit.enabled: true`. Значение ≤ 0 или отсутствие поля у внешнего токена означает `rate_limit.default_rps`, а не отсутствие лимита. Изменение квоты в БД требует нового локального JWT; при внешнем IdP значение задаётся в токене или ответе introspection.

### RBAC

| Роль | Права |
|------|-------|
| `admin` | rules R/W, users R/W, stats, proxy |
| `moderator` | rules R/W, stats, proxy |
| `user` | rules R, stats, proxy |
| `guest` | только proxy |

### Правила фильтрации

- Действия: `allow`, `block`, `modify`.
- Правила проверяются по убыванию `priority`; применяется первое совпавшее правило.
- Условия: `AND` / `OR` / `NOT` и листовые операторы (`eq`, `in`, `regex`, …).
- Поля: `method`, `url`, `path`, `query`, `host`, `ip`, `content_type`, `body_size`, `body`, `header.*`, `user_id`, `role`.
- `AND`/`OR` без дочерних условий отклоняется валидацией.

Подробнее: [admin-guide.md](./admin-guide.md).

### Безопасность

- SSRF: private/loopback/link-local/CGNAT/ULA/localhost блокируются при `allow_private_targets: false`.
- При HTTP forward `Authorization` и hop-by-hop-заголовки удаляются перед отправкой upstream. Заголовки внутри TLS-туннеля не обрабатываются.
- SSRF-проверка выполняет отдельное DNS-разрешение до подключения; проверенный IP не закрепляется за dialer. Поэтому полную защиту от DNS rebinding текущая реализация не гарантирует.
- XFF учитывается только от `trusted_proxies`.
- Обновление `active`, `role` или `quota_rps` в PostgreSQL не меняет поля ранее выданных JWT. В текущем `updateUser` переопределение активности в кэше записывается и сразу удаляется, поэтому немедленная деактивация не обеспечивается. Удаление пользователя также не отзывает его токены.

### Масштабирование

- Локальных пользовательских сессий нет, но правила, кэш, ограничители и соединения имеют состояние в памяти процесса. Открытые туннели не переносятся между репликами.
- При доступном Redis используется общий счётчик RPS с секундным окном. При отключении Redis или ошибке счётчика - локальный token bucket; общий лимит кластера тогда не гарантируется.
- Перед несколькими репликами - LB (пример HAProxy: `deploy/haproxy/`).

### Наблюдаемость

- `:9090/metrics` - Prometheus.
- `:8081/health`, `:8081/ready` - liveness/readiness (ready = установлен внутренний флаг запуска; текущая доступность БД, Redis и IdP не проверяется).
- Аудит действий асинхронно записывается в PostgreSQL и публикуется в Kafka, если она включена. Журналы запросов публикуются при включённой Kafka; запись в PostgreSQL отдельно включается флагом `log.persist_requests: true`. Попадания в кэш ответов и отказы при аутентификации и проверке лимитов до фильтрации не записываются в `request_logs`.

---

## 4. Запуск для разработки и тестирования

### Требования

- Go **1.27+**
- Docker Compose
- OpenSSL (секреты)
- Python 3 (пример извлечения `access_token`)
- `hey` для load-test (`make hey-install`)

### 4.1. Инфраструктура

```bash
docker compose up -d postgres redis
```

При инициализации пустого тома PostgreSQL Compose выполняет только `migrations/000001_init.up.sql`, подключённый в `docker-entrypoint-initdb.d`. На существующем томе он повторно не выполняется.

Compose выполняет начальный SQL напрямую и не ведёт историю golang-migrate. Не запускайте `migrate-up` поверх такой схемы без согласования версии: история версий останется несогласованной с ручным применением схемы. Начальный SQL использует `IF NOT EXISTS`, но это не заменяет управление версиями миграций. Для БД, управляемой golang-migrate, используйте:

```bash
make migrate-install
make migrate-up
```

Пользователь по умолчанию: `admin@guardian.local` (роль `admin`).

### 4.2. Секреты и запуск бинарника

```bash
export GUARDIAN_AUTH_JWT_SECRET="$(openssl rand -hex 32)"
export GUARDIAN_AUTH_BOOTSTRAP_TOKEN="$(openssl rand -hex 16)"
export GUARDIAN_LOG_FORMAT=console   # удобнее в терминале

go mod download
make run
# эквивалент: go build -o bin/guardian ./cmd/proxy && ./bin/guardian -config configs/config.yaml
```

Проверка:

```bash
curl -s http://127.0.0.1:8081/health
curl -s http://127.0.0.1:8081/ready
curl -x http://127.0.0.1:8080 http://example.com/
```

### 4.3. Bootstrap JWT и правило

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8081/api/v1/auth/token \
  -H "X-Bootstrap-Token: $GUARDIAN_AUTH_BOOTSTRAP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@guardian.local"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://127.0.0.1:8081/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Block malicious IPs",
    "priority": 100,
    "enabled": true,
    "conditions": {
      "operator": "AND",
      "rules": [
        {"field": "ip", "operator": "in", "value": ["1.2.3.4"]},
        {"field": "method", "operator": "in", "value": ["POST","PUT"]}
      ]
    },
    "action": "block",
    "response": {"status": 403, "body": "Access denied"}
  }'
```

### 4.4. Запуск всего стека в Docker

```bash
make docker-up
# compose.yaml использует собственные локальные bootstrap/HS256-секреты;
# экспортированные ранее переменные хоста не заменяют эти значения автоматически.
# или: docker compose up -d --build postgres redis proxy
```

Профили:

```bash
# Запуск Kafka сам по себе не включает публикацию: настройте для proxy
# GUARDIAN_QUEUE_ENABLED=true, GUARDIAN_QUEUE_BACKEND=kafka,
# GUARDIAN_QUEUE_BROKERS=kafka:9092 через compose override и пересоздайте proxy.
docker compose --profile kafka up -d
docker compose --profile monitoring up -d   # Prometheus :9091, Grafana :3000
```

### 4.5. Тесты и качество

```bash
make test                 # go test ./...
make lint                 # golangci-lint (см. .golangci.yaml)
make openapi-check        # актуальный docs/openapi.yaml
make load-test            # hey через HTTP-прокси
```

Корректный load-test (обязательно `-x` с схемой `http://`):

```bash
hey -n 10000 -c 100 -x http://127.0.0.1:8080 http://example.com/
```

При превышении лимитов возможны **429**. Конкурентность `-c` не задаёт RPS напрямую; `-q` ограничивает RPS на каждого воркера `hey`. Проверяйте тело ответа для определения источника `429`: его может вернуть также upstream или block-правило. Уменьшение нагрузки не гарантирует `200` при ошибках upstream или запрещающих правилах.

### 4.6. Postman / клиенты

Прокси задаётся **настройками клиента** (Proxy = `127.0.0.1:8080`), а URL запроса - целевой (`http://example.com/`).  
Не используйте `http://127.0.0.1:8080/http://example.com/` - Guardian воспримет Host `127.0.0.1` и вернёт SSRF **403**.

---

## 5. Запуск в рабочем окружении

### 5.1. Подготовка к развёртыванию

- [ ] Сильный `GUARDIAN_AUTH_JWT_SECRET` (или чистый OAuth2 без локального bootstrap)
- [ ] `auth.bootstrap_token` **пустой** / не задан
- [ ] `proxy.allow_private_targets: false`
- [ ] `auth.require_auth_for_proxy` - по политике безопасности
- [ ] При внешнем IdP: `oauth2_enabled: true` + `oauth2_jwks_url` и/или `oauth2_introspect_url`
- [ ] `server.trusted_proxies` = CIDR балансировщиков
- [ ] PostgreSQL с SSL и миграциями; секреты не в git
- [ ] Redis для кэша/кластерного rate limit
- [ ] `cache.response_enabled: false` (пока нет явной необходимости)
- [ ] `log.persist_requests` выбран с учётом нагрузки и нужной статистики; аудит действий записывается в PostgreSQL независимо от этого флага, Kafka включается отдельно
- [ ] TLS на LB (Guardian по умолчанию слушает plain HTTP)
- [ ] Доступ к Admin API (`:8081`) ограничен ACL, mTLS или VPN
- [ ] Probes: liveness `/health`, readiness `/ready` на **admin** порту
- [ ] HPA / несколько реплик + LB

### 5.2. Пример настроек для внешнего IdP

```bash
# В чистом OAuth2-режиме с bootstrap_token="" локальный jwt_secret не требуется
unset GUARDIAN_AUTH_BOOTSTRAP_TOKEN # в YAML auth.bootstrap_token должен быть пустым
export GUARDIAN_AUTH_OAUTH2_ENABLED=true
export GUARDIAN_AUTH_OAUTH2_JWKS_URL="https://idp.example.com/.well-known/jwks.json"
export GUARDIAN_AUTH_JWT_ISSUER="https://idp.example.com/" # точное значение iss вашего IdP
export GUARDIAN_AUTH_REQUIRE_AUTH_FOR_PROXY=true
export GUARDIAN_PROXY_ALLOW_PRIVATE_TARGETS=false
export GUARDIAN_SERVER_TRUSTED_PROXIES="10.0.0.5/32" # замените на IP/CIDR доверенного LB
export GUARDIAN_POSTGRES_DSN="postgres://...@db:5432/guardian?sslmode=require"
export GUARDIAN_REDIS_ENABLED=true
export GUARDIAN_REDIS_ADDR="redis:6379"
export GUARDIAN_LOG_FORMAT=json
export GUARDIAN_LOG_LEVEL=info
export GUARDIAN_QUEUE_ENABLED=true
export GUARDIAN_QUEUE_BACKEND=kafka
export GUARDIAN_QUEUE_BROKERS="kafka-1:9092,kafka-2:9092"
```

### 5.3. Контейнер

Образ собирается из корневого `Dockerfile` (Go 1.27 multi-stage -> alpine).

```bash
docker build -t guardian:latest .
docker run --rm -p 8080:8080 -p 8081:8081 -p 9090:9090 \
  -e GUARDIAN_AUTH_JWT_SECRET=... \
  -e GUARDIAN_POSTGRES_DSN=... \
  -e GUARDIAN_REDIS_ADDR=redis:6379 \
  guardian:latest
```

### 5.4. Kubernetes

Пример: `deploy/k8s/deployment.yaml` - Deployment с 3 репликами, Service, HPA по CPU, проверки состояния на административном порту и аннотации сбора метрик Prometheus.

Секреты вынесите в `Secret` (`postgres-dsn`, `jwt-secret`). Не храните их в манифестах репозитория.

### 5.5. Балансировщик

Пример HAProxy: `deploy/haproxy/haproxy.cfg` - round-robin на proxy, health-check `GET /ready` на admin-порту бэкендов.

Клиенты должны ходить на LB как на **HTTP-прокси** (`Proxy` / `-x`), а не как на reverse-proxy с path-prefix URL.

### 5.6. Миграции БД

Перед выкладкой новой версии:

```bash
DATABASE_URL='postgres://.../guardian?sslmode=require' make migrate-up
```

### 5.7. Завершение работы

- `SIGINT` / `SIGTERM` -> graceful shutdown (`shutdown_timeout`), закрытие queue и пулов БД.
- `ready` становится `false` в начале shutdown.

---

## 6. Эндпоинты

Guardian слушает **три порта**. OpenAPI ([openapi.yaml](./openapi.yaml)) описывает Admin API (`:8081`). Прокси и метрики - по фактическому коду.

Общие правила Admin API:

- база: `http://<host>:8081`;
- где указан Bearer - заголовок `Authorization: Bearer <jwt>`;
- ошибки обычно `{"error":"<текст>"}`;
- сбои репозитория обычно возвращают `500`; таблицы ниже перечисляют основные ошибки, а не исчерпывающий набор;
- пагинация: `page` по умолчанию 1, `limit` по умолчанию 20; используйте `limit` от 1 до 100. Для значений > 100 текущий код ограничивает OFFSET, но не LIMIT, что нарушает согласованность страниц;
- права RBAC: `rules:read` / `rules:write`, `users:read` / `users:write`, `stats:read`, `proxy:access`.

---

### 6.1. Прокси - порт `:8080`

Отдельных REST-путей нет: порт работает как **HTTP-прокси**.

#### HTTP forward

| | |
|--|--|
| **Назначение** | Проксирование обычного HTTP к upstream |
| **Как вызывать** | Клиент в режиме proxy: `curl -x http://127.0.0.1:8080 http://example.com/` |
| **Auth** | Опционально `Authorization: Bearer <jwt>`. Обязателен, если `require_auth_for_proxy: true` |
| **Успех** | Ответ upstream (статус/тело), при необходимости изменённый правилом `modify`; для подходящего анонимного GET возможен ответ из кэша |
| **Типичные ошибки** | `401` - токен отсутствует или невалиден при `require_auth_for_proxy: true`; `403` - SSRF либо у распознанной роли нет права `proxy:access`; block-правило - статус из правила (`403` по умолчанию); `413` - превышен размер тела; `429` - превышен rate limit по IP, пользовательская квота или лимит соединений; `502` - ошибка подключения или обмена с upstream |

Если `require_auth_for_proxy: false`, отсутствующий или невалидный токен не вызывает `401`: запрос продолжает обрабатываться как анонимный. Перед upstream снимаются hop-by-hop-заголовки, `Authorization` и `Proxy-Authorization`. Filter Engine применяется до пересылки; при ответе из кэша новая SSRF-проверка не выполняется.

#### HTTPS CONNECT

| | |
|--|--|
| **Назначение** | TCP-туннель для HTTPS (и любого TLS) |
| **Как вызывать** | `curl -x http://127.0.0.1:8080 https://example.com/` |
| **Auth / лимиты** | Применяются к запросу CONNECT. Для curl передавайте токен прокси через `--proxy-header "Authorization: Bearer <jwt>"`; обычный `-H` относится к запросу внутри TLS-туннеля |
| **Успех** | `200`, далее TCP-туннель; содержимое TLS не расшифровывается |
| **Ошибки** | Auth, правила и rate limit - как у HTTP forward; ошибка открытия туннеля, включая SSRF-блокировку цели, сейчас возвращает `502` |

**Нельзя:** `GET http://127.0.0.1:8080/http://example.com/` - Host будет `127.0.0.1`, сработает SSRF.

---

### 6.2. Admin API - порт `:8081`

Источник правил вызова: [openapi.yaml](./openapi.yaml).

#### Служебные

##### `GET /health`

| | |
|--|--|
| **Назначение** | Liveness: процесс жив |
| **Auth** | Нет |
| **Ответ** | `200` `{"status":"ok"}` |
| **Использование** | Kubernetes livenessProbe, мониторинг |

##### `GET /ready`

| | |
|--|--|
| **Назначение** | Readiness: готов принимать трафик |
| **Auth** | Нет |
| **Ответ** | `200` `{"status":"ready"}`; `503` если ещё не готов / идёт shutdown |
| **Использование** | readinessProbe, health-check балансировщика |

#### Аутентификация

##### `POST /api/v1/auth/token`

| | |
|--|--|
| **Назначение** | Выпуск JWT для разработки (bootstrap) |
| **Условие** | Задан `auth.bootstrap_token`; иначе `404` |
| **Заголовки** | `X-Bootstrap-Token` (обязателен), `Content-Type: application/json` |
| **Тело** | `{"email":"<существующий email>"}` |
| **Ответ** | `200` `{"access_token":"...","token_type":"Bearer"}` |
| **Ошибки** | `400` нет email; `401` неверный bootstrap; `403` user inactive; `404` bootstrap выключен или user not found |

##### `POST /api/v1/auth/logout`

| | |
|--|--|
| **Назначение** | Запрет использования предъявленного токена в Guardian на 24 часа. Токен у IdP не отзывается |
| **Auth** | Bearer (валидный токен) |
| **Ответ** | `204` без тела |
| **Ошибки** | `401` нет/невалидный токен; `500` сбой отзыва |

#### Правила фильтрации

Права: чтение - `rules:read`; изменение - `rules:write`.

##### `GET /api/v1/rules`

| | |
|--|--|
| **Назначение** | Список правил (страница) |
| **Query** | `page` (int), `limit` (int) |
| **Auth** | Bearer + `rules:read` |
| **Ответ** | `200` страница: `items`, `total`, `page`, `limit`, `total_pages` |
| **Ошибки** | `401`, `403` |

##### `POST /api/v1/rules`

| | |
|--|--|
| **Назначение** | Создание правила |
| **Auth** | Bearer + `rules:write` |
| **Тело** | Rule: обязательны `name`, `conditions`, `action` (`allow`\|`block`\|`modify`); задавайте также `priority` и `enabled` (при пропуске - `0` и `false`); опционально `response`, `modify` |
| **Ответ** | `201` созданное правило |
| **Ошибки** | `400` невалидный JSON/условия; `401`, `403` |

##### `GET /api/v1/rules/{id}`

| | |
|--|--|
| **Назначение** | Получение правила |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `rules:read` |
| **Ответ** | `200` правило; `404` не найдено |
| **Ошибки** | `400` при невалидном UUID; `401`, `403`, `404` |

##### `PUT /api/v1/rules/{id}`

| | |
|--|--|
| **Назначение** | Изменение правила |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `rules:write` |
| **Тело** | Полный набор редактируемых полей правила; пропущенные поля обнуляются |
| **Ответ** | `200` обновлённое правило |
| **Ошибки** | `400`, `401`, `403`, `404` |

##### `DELETE /api/v1/rules/{id}`

| | |
|--|--|
| **Назначение** | Удаление правила |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `rules:write` |
| **Ответ** | `204` |
| **Ошибки** | `400` при невалидном UUID; `401`, `403`, `404` |

##### `POST /api/v1/rules/{id}/test`

| | |
|--|--|
| **Назначение** | Проверить, сработает ли правило на заданном контексте (без проксирования) |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `rules:read` |
| **Тело** | `RequestContext`: `method`, `url`, `path`, `query`, `host`, `ip`, `headers`, `body` (Base64-строка), `content_type`, `body_size`, `user_id`, `role`. Поля задаются независимо и не вычисляются автоматически |
| **Ответ** | `200` объект `{"matched":true,"action":"block"}` с фактическими значениями |
| **Ошибки** | `400` при невалидном UUID; `401`, `403`, `404` |

#### Пользователи

Права: чтение - `users:read`; изменение - `users:write` (обычно роль `admin`).

##### `GET /api/v1/users`

| | |
|--|--|
| **Назначение** | Список пользователей |
| **Query** | `page`, `limit` |
| **Auth** | Bearer + `users:read` |
| **Ответ** | `200` страница пользователей |
| **Ошибки** | `401`, `403` |

##### `POST /api/v1/users`

| | |
|--|--|
| **Назначение** | Создание пользователя |
| **Auth** | Bearer + `users:write` |
| **Тело** | User: `email`, `role`, `active`, `quota_rps`, … |
| **Ответ** | `201` пользователь: `active` принудительно `true`; если `quota_rps` = 0, подставляется 1000 |
| **Ошибки** | `400`, `401`, `403` |

##### `GET /api/v1/users/{id}`

| | |
|--|--|
| **Назначение** | Получение пользователя |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `users:read` |
| **Ответ** | `200` / `404` |
| **Ошибки** | `400` при невалидном UUID; `401`, `403`, `404` |

##### `PUT /api/v1/users/{id}`

| | |
|--|--|
| **Назначение** | Изменение пользователя (в т.ч. `active`, `quota_rps`, `role`) |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `users:write` |
| **Тело** | Полный объект User: пропущенные поля получают нулевые значения; это не частичное обновление |
| **Ответ** | `200` |
| **Ошибки** | `400`, `401`, `403`, `404` |
| **Особенность** | Изменение пользователя не обновляет поля ранее выданных JWT. Переопределение активности в кэше сразу удаляется вызовом `InvalidateUserCache`, поэтому изменение `active` не обеспечивает немедленный отзыв токенов |

##### `DELETE /api/v1/users/{id}`

| | |
|--|--|
| **Назначение** | Удаление пользователя |
| **Path** | `id` - UUID |
| **Auth** | Bearer + `users:write` |
| **Ответ** | `204` |
| **Ошибки** | `400` при невалидном UUID; `401`, `403`, `404` |

#### Статистика

Право: `stats:read`.

##### `GET /api/v1/stats`

| | |
|--|--|
| **Назначение** | Сводка текущего экземпляра: total/blocked requests, active connections/tunnels; сбрасывается при перезапуске |
| **Auth** | Bearer + `stats:read` |
| **Ответ** | `200` объект Stats; `by_method` и `by_status` сейчас `null` |
| **Ошибки** | `401`, `403` |

##### `GET /api/v1/stats/rules`

| | |
|--|--|
| **Назначение** | До 100 правил по числу записей с `rule_id` из `request_logs` (hits, avg_ms), включая allow/block/modify |
| **Auth** | Bearer + `stats:read` |
| **Ответ** | `200` массив `{rule_id, hits, avg_ms}` |
| **Ошибки** | `401`, `403`; пусто, если логи в PG не пишутся |

##### `GET /api/v1/stats/users`

| | |
|--|--|
| **Назначение** | До 100 пользователей по числу записей с `user_id` из `request_logs` |
| **Auth** | Bearer + `stats:read` |
| **Ответ** | `200` массив `{user_id, requests, avg_ms}` |
| **Ошибки** | `401`, `403` |

**CRUD** для rules/users - набор Create/Read/Update/Delete (`POST` / `GET` / `PUT` / `DELETE`), не отдельный HTTP-метод.

---

### 6.3. Метрики и health - порт `:9090`

| Метод | Путь | Назначение | Auth |
|-------|------|------------|------|
| GET | `/metrics` | Экспорт Prometheus | Нет |
| GET | `/health` | Простой health (`{"status":"ok"}`) | Нет |

`/ready` на этом порту **нет** - только на `:8081`.

---

### 6.4. Мониторинг Prometheus

#### Формат и состав метрик

Текстовый exposition format. Основные серии Guardian:

| Метрика | Тип | Смысл |
|---------|-----|--------|
| `guardian_requests_total` | counter | Число запросов (`method`, `status`) |
| `guardian_request_duration_seconds` | histogram | Задержка (`method`) |
| `guardian_active_connections` | gauge | Активные обработки сейчас |
| `guardian_active_tunnels` | gauge | Активные CONNECT-туннели |
| `guardian_bytes_in_total` | counter | Для HTTP - байты тела ответа; для туннелей - переданные байты от upstream |
| `guardian_bytes_out_total` | counter | Для HTTP - байты исходного тела запроса; для туннелей - переданные байты к upstream |
| `guardian_blocked_requests_total` | counter | Заблокированные правилами |
| `guardian_rule_hits_total` | counter | Только блокировки правилом (`rule_id`, `rule_name`); `allow`/`modify` не учитываются |

Для CONNECT длительность означает время открытия туннеля, а не его жизни. Запросы внутри туннеля отдельно не учитываются. Активные подключения и туннели относятся к текущему экземпляру; фоновые значения обновляются каждые 5 секунд. Байты туннелей добавляются после завершения копирования в соответствующем направлении.

Дополнительно экспортируются стандартные метрики процесса и Go runtime.

#### Подключение мониторинга

1. **Prometheus** опрашивает `:9090/metrics` (пример: `deploy/prometheus/prometheus.yml`, job `guardian` -> `proxy:9090`).
2. **Kubernetes**: аннотации `prometheus.io/scrape`, `prometheus.io/port: "9090"` в `deploy/k8s/`.
3. **Grafana** (профиль `monitoring` в compose) - источник Prometheus и дашборды нужно настроить; готовая настройка не поставляется.

Проверка вручную:

```bash
curl -s http://127.0.0.1:9090/metrics | head
```

#### Запросы PromQL и оповещения

Примеры PromQL:

```promql
# RPS
sum(rate(guardian_requests_total[1m]))

# Доля блокировок
sum(rate(guardian_blocked_requests_total[5m]))
  / sum(rate(guardian_requests_total[5m]))

# p95 задержки
histogram_quantile(0.95, sum(rate(guardian_request_duration_seconds_bucket[5m])) by (le, method))

# 5xx
sum(rate(guardian_requests_total{status=~"5.."}[5m]))

# Активные туннели
guardian_active_tunnels
```

Для оповещений используйте следующие показатели; пороги зависят от штатной нагрузки:

- резкий рост `guardian_blocked_requests_total` (изменение трафика или ошибка в правилах);
- рост `5xx` в `guardian_requests_total`;
- аномально высокий `guardian_active_connections` / `guardian_active_tunnels`;
- ошибки опроса `/metrics` и отказ `/ready` на административном порту.

#### Журналы и статистика БД

Метрики содержат агрегаты по экземпляру. Для разбора отдельных запросов нужны `request_logs` или события Kafka; для статистики правил из PostgreSQL - `GET /api/v1/stats/rules` и включённая запись журналов. Охват этих данных отличается от метрик: попадания в кэш и отказы до фильтрации в журнал запросов не записываются.

---

## 7. Типовые проблемы

| Симптом | Причина | Что делать |
|---------|---------|------------|
| `destination blocked: private or local address` | Цель private/local или Host = `127.0.0.1` | Использовать `-x http://127.0.0.1:8080 http://example.com/`, не path-URL |
| `401` на Admin | Токен отсутствует или не прошёл проверку | Передать токен настроенного режима аутентификации |
| `404` на `/api/v1/auth/token` | Пустой `bootstrap_token` | Задать только в dev |
| `429` под нагрузкой | Rate limit / max conns per IP | Снизить concurrency или поднять лимиты |
| Слабый/пустой JWT secret при старте | Проверка `WeakSecret` | Задать `GUARDIAN_AUTH_JWT_SECRET` |
| Подставленный клиентом XFF не влияет на IP в правилах | Пустой `trusted_proxies` или недоверенный TCP peer | Используется IP TCP-соединения; при работе через LB проверьте список доверенных адресов |
| Redis недоступен | Используются локальный кэш и ограничители RPS | Проверить `GUARDIAN_REDIS_*`; общий лимит RPS кластера перестаёт действовать |

---

## 8. Команды Makefile

| Цель | Действие |
|------|----------|
| `make help` / `make` | Список целей, переменных и примеры запуска |
| `make run` | Сборка + запуск с `configs/config.yaml` |
| `make test` | Юнит-тесты |
| `make lint` | golangci-lint |
| `make openapi` / `openapi-check` | Генерация / проверка OpenAPI |
| `make migrate-up` / `migrate-down` | Миграции PG |
| `make docker-up` / `docker-down` | Compose proxy+deps |
| `make docker-monitoring` | Prometheus + Grafana |
| `make load-test` | Нагрузка через `hey` + HTTP proxy |
| `make hey-install` | Установка `hey` |

---

## 9. Карта репозитория

```
cmd/proxy          - точка входа
cmd/openapi        - генератор OpenAPI
internal/api       - обработчики прокси и Admin API
internal/auth      - JWT, RBAC, лимиты RPS, проверка токенов IdP
internal/filter    - Filter Engine
internal/proxy     - forward / CONNECT / SSRF
internal/repository - доступ к PostgreSQL
internal/cache     - Redis и локальный кэш
internal/queue     - Kafka / Nop
internal/server    - сборка зависимостей, запуск и остановка
configs/           - config.yaml
migrations/        - SQL
deploy/            - k8s, haproxy, prometheus
docs/              - документация
```
