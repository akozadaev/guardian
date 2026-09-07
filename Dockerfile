# Многоэтапная сборка прокси-сервера Guardian
FROM golang:1.27-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /guardian ./cmd/proxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl
WORKDIR /app
COPY --from=builder /guardian /app/guardian
COPY configs/config.yaml /app/configs/config.yaml
COPY migrations /app/migrations
EXPOSE 8080 8081 9090
ENTRYPOINT ["/app/guardian", "-config", "/app/configs/config.yaml"]
