.PHONY: build run test tidy generate openapi openapi-check migrate-install migrate-up migrate-down hey-install load-test docker-up docker-down docker-monitoring lint lint-install

APP=guardian
CONFIG?=configs/config.yaml
GOLANGCI_LINT_VERSION?=v2.13.2
GOLANGCI_LINT_BIN=bin/golangci-lint
GOLANGCI_LINT_CACHE=$(CURDIR)/bin/.cache/golangci-lint
GOLANGCI_LINT_GO_CACHE=$(CURDIR)/bin/.cache/go-build

build:
	go build -o bin/$(APP) ./cmd/proxy

run: build
	./bin/$(APP) -config $(CONFIG)

test:
	go test ./...

lint: $(GOLANGCI_LINT_BIN)
	GOCACHE=$(GOLANGCI_LINT_GO_CACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT_BIN) run ./...

lint-install:
	curl -sSfL https://golangci-lint.run/install.sh -o bin/golangci-lint-install.sh
	sh bin/golangci-lint-install.sh -b ./bin $(GOLANGCI_LINT_VERSION)
	rm bin/golangci-lint-install.sh

$(GOLANGCI_LINT_BIN):
	$(MAKE) lint-install

tidy:
	go mod tidy

generate:
	go generate ./...

openapi:
	go run ./cmd/openapi -output docs/openapi.yaml

openapi-check:
	go generate ./...
	git diff --exit-code -- docs/openapi.yaml

migrate-install:
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

migrate-up:
	migrate -path migrations -database "$${DATABASE_URL:-postgres://guardian:guardian@localhost:5432/guardian?sslmode=disable}" up

migrate-down:
	migrate -path migrations -database "$${DATABASE_URL:-postgres://guardian:guardian@localhost:5432/guardian?sslmode=disable}" down 1

docker-up:
	docker compose up -d --build postgres redis
	@echo "Waiting for postgres..."; sleep 3
	docker compose up -d --build proxy

docker-down:
	docker compose down

docker-monitoring:
	docker compose --profile monitoring up -d

hey-install:
	go install github.com/rakyll/hey@latest

load-test:
	@echo "Example: hey -n 100000 -c 200 -x http://127.0.0.1:8080 http://example.com/"
	hey -n 10000 -c 100 -x http://127.0.0.1:8080 http://example.com/
