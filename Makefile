# Guardian — HTTP/HTTPS фильтрующий прокси
#
# Использование: make <цель>
# Справка:       make help  (цель по умолчанию)

.DEFAULT_GOAL := help

.PHONY: help build run test tidy generate openapi openapi-check \
	migrate-install migrate-up migrate-down \
	hey-install load-test \
	docker-up docker-down docker-monitoring \
	lint lint-install

APP=guardian
CONFIG?=configs/config.yaml
GOLANGCI_LINT_VERSION?=v2.13.2
GOLANGCI_LINT_BIN=bin/golangci-lint
GOLANGCI_LINT_CACHE=$(CURDIR)/bin/.cache/golangci-lint
GOLANGCI_LINT_GO_CACHE=$(CURDIR)/bin/.cache/go-build

help: ## показать список целей и краткое описание
	@echo "Guardian — цели Makefile"
	@echo ""
	@echo "Использование: make <цель> [ПЕРЕМЕННАЯ=значение]"
	@echo "Примеры: make build; make run CONFIG=configs/config.yaml"
	@echo ""
	@echo "Переменные:"
	@echo "  CONFIG=$(CONFIG) — конфигурация для run"
	@echo "  GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION) — версия линтера"
	@echo "  DATABASE_URL — URL PostgreSQL для migrate-up/migrate-down"
	@echo "    По умолчанию: postgres://guardian:guardian@localhost:5432/guardian?sslmode=disable"
	@echo ""
	@echo "Цели:"
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## собрать бинарник в bin/guardian
	go build -o bin/$(APP) ./cmd/proxy

run: build ## собрать и запустить с CONFIG (по умолчанию configs/config.yaml)
	./bin/$(APP) -config $(CONFIG)

test: ## запустить go test ./...
	go test ./...

lint: $(GOLANGCI_LINT_BIN) ## прогнать golangci-lint (при необходимости установит бинарник)
	GOCACHE=$(GOLANGCI_LINT_GO_CACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT_BIN) run ./...

lint-install: ## установить golangci-lint в bin/
	curl -sSfL https://golangci-lint.run/install.sh -o bin/golangci-lint-install.sh
	sh bin/golangci-lint-install.sh -b ./bin $(GOLANGCI_LINT_VERSION)
	rm bin/golangci-lint-install.sh

$(GOLANGCI_LINT_BIN):
	$(MAKE) lint-install

tidy: ## go mod tidy
	go mod tidy

generate: ## go generate ./... (в т.ч. OpenAPI из routes)
	go generate ./...

openapi: ## сгенерировать docs/openapi.yaml
	go run ./cmd/openapi -output docs/openapi.yaml

openapi-check: ## проверить, что docs/openapi.yaml актуален (для CI)
	go generate ./...
	git diff --exit-code -- docs/openapi.yaml

migrate-install: ## установить golang-migrate
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

migrate-up: ## применить миграции PostgreSQL
	migrate -path migrations -database "$${DATABASE_URL:-postgres://guardian:guardian@localhost:5432/guardian?sslmode=disable}" up

migrate-down: ## откатить одну миграцию PostgreSQL
	migrate -path migrations -database "$${DATABASE_URL:-postgres://guardian:guardian@localhost:5432/guardian?sslmode=disable}" down 1

docker-up: ## поднять postgres, redis и proxy через compose
	docker compose up -d --build postgres redis
	@echo "Waiting for postgres..."; sleep 3
	docker compose up -d --build proxy

docker-down: ## остановить compose-стек
	docker compose down

docker-monitoring: ## поднять Prometheus и Grafana (profile monitoring)
	docker compose --profile monitoring up -d

hey-install: ## установить утилиту нагрузочного теста hey
	go install github.com/rakyll/hey@latest

load-test: ## нагрузка через hey (HTTP-прокси на :8080 → example.com)
	@echo "Example: hey -n 100000 -c 200 -x http://127.0.0.1:8080 http://example.com/"
	hey -n 10000 -c 100 -x http://127.0.0.1:8080 http://example.com/
