.PHONY: build run test tidy migrate-install migrate-up migrate-down hey-install load-test docker-up docker-down lint

APP=guardian
CONFIG?=configs/config.yaml

build:
	go build -o bin/$(APP) ./cmd/proxy

run: build
	./bin/$(APP) -config $(CONFIG)

test:
	go test ./...

tidy:
	go mod tidy

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
	@echo "Example: hey -n 100000 -c 200 -m GET http://127.0.0.1:8080/http://example.com/"
	hey -n 10000 -c 100 http://127.0.0.1:8080/http://example.com/ || true
