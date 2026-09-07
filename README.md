# Guardian - высокопроизводительный HTTP/HTTPS прокси с фильтрацией

Прокси-сервер на Go + `fasthttp` для фильтрации HTTP-трафика, RBAC/JWT, PostgreSQL, Redis и Prometheus.

## Практическое назначение

Контролируемый исходящий HTTP(S)-прокси: трафик приложений или пользователей идёт через Guardian, политики задаются централизованно.

- резать опасные и ненужные запросы по IP, URL, методу, заголовкам, телу (allow / block / modify);
- блокировать SSRF (внутренние сети, localhost, cloud metadata);
- ограничивать доступ и квоты (JWT/OAuth2, RPS на пользователя и IP);
- управлять правилами через Admin API без правок конфигов на каждой машине;
- наблюдать трафик (Prometheus, опционально логи / Kafka, статистика по правилам).

Типичное место — между корпоративными сервисами (или пользователями) и интернетом / внешними API: шлюз с ACL, а не замена Nginx как reverse-proxy для своих сайтов.

## Что можно заблокировать / разрешить

Через правила фильтрации (allow / block / modify) — по атрибутам запроса:

| Поле | Примеры |
|------|---------|
| `method` | запретить POST/PUT |
| `url` / `path` / `query` / `host` | домены, пути, query-параметры |
| `ip` | клиентский IP (в т.ч. CIDR в `in`) |
| `header.*` | User-Agent, Referer и др. |
| `content_type`, `body`, `body_size` | тип и тело запроса |
| `user_id`, `role` | кто ходит (если есть JWT) |

Условия комбинируются через **AND / OR / NOT**; операторы: `eq`, `neq`, `in`, `not_in`, `contains`, `prefix`, `regex`, `gt`, `lt`, `exists`.

Действия:

- **block** — отказ (свой status/body);
- **allow** — пропустить при совпадении;
- **modify** — менять заголовки запроса / подменить тело ответа.

Без совпадения правила запрос по умолчанию пропускается (allow).

Отдельно от правил (при `allow_private_targets: false`): нельзя ходить на private/loopback/metadata — это SSRF-защита.

## Возможности

- HTTP forwarding и HTTPS CONNECT tunneling
- Блокировка SSRF (private/loopback/metadata) - `proxy.allow_private_targets: false`
- Filter Engine: method/URL/headers/IP/body, AND/OR/NOT, приоритеты
- JWT + RBAC, квоты в токене, rate limit, лимит соединений на IP
- Trusted proxies для X-Forwarded-For (без spoofing с клиента)
- Admin REST API (`/api/v1/rules`, `/api/v1/users`, `/api/v1/stats`)
- PostgreSQL, Redis-кэш, опционально Kafka
- Метрики Prometheus (`:9090/metrics`), `/health` и `/ready` на Admin API

## Порты

| Порт | Назначение |
|------|------------|
| 8080 | Прокси |
| 8081 | Admin API, `/health`, `/ready` |
| 9090 | Prometheus `/metrics`, `/health` |

## Требования

- Go 1.27 или новее
- Docker Compose
- OpenSSL для генерации секретов из примеров
- Python 3 для извлечения `access_token` в примере bootstrap JWT

## Быстрый старт

```bash
docker compose up -d postgres redis

export GUARDIAN_AUTH_JWT_SECRET="$(openssl rand -hex 32)"
# опционально для выдачи bootstrap-токена (только dev):
export GUARDIAN_AUTH_BOOTSTRAP_TOKEN="$(openssl rand -hex 16)"

go mod download
make run
```

### Bootstrap JWT (только если задан `bootstrap_token`)

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8081/api/v1/auth/token \
  -H "X-Bootstrap-Token: $GUARDIAN_AUTH_BOOTSTRAP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@guardian.local"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Без `auth.bootstrap_token` эндпоинт отвечает `404`. В production включите внешний OAuth2/IdP: `auth.oauth2_enabled: true` и задайте `auth.oauth2_introspect_url` или `auth.oauth2_jwks_url`.

### Правило фильтрации

```bash
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

### Проксирование

```bash
curl -x http://127.0.0.1:8080 http://example.com/
```

Запросы к `127.0.0.1` / RFC1918 / metadata IP отклоняются (`403`), пока `allow_private_targets: false`.

## Безопасность (важно)

| Тема | Поведение |
|------|-----------|
| JWT secret | Обязателен при локальном JWT/bootstrap (≥16 символов, не дефолтный) |
| Bootstrap token | Dev-only, заголовок `X-Bootstrap-Token` |
| X-Forwarded-For | Учитывается только от `server.trusted_proxies` |
| Authorization | Не проксируется на upstream |
| Response cache | Выключен по умолчанию; кэшируются только анонимные GET без `Cookie` и `Authorization`, если ответ содержит `Cache-Control: public` и не содержит `Set-Cookie` или `Vary` |
| Request logs в PG | `log.persist_requests: false` по умолчанию (hot path) |

## Конфигурация

`configs/config.yaml` + env `GUARDIAN_*`
Примеры: `configs/config.local.env.example`.
