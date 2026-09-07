// Package config загружает и описывает конфигурацию Guardian.
package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config содержит всю конфигурацию приложения.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Proxy     ProxyConfig     `mapstructure:"proxy"`
	Postgres  PostgresConfig  `mapstructure:"postgres"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Auth      AuthConfig      `mapstructure:"auth"`
	Cache     CacheConfig     `mapstructure:"cache"`
	Queue     QueueConfig     `mapstructure:"queue"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	Log       LogConfig       `mapstructure:"log"`
}

// ServerConfig задаёт параметры прокси-, admin- и metrics-серверов.
type ServerConfig struct {
	ProxyAddr       string        `mapstructure:"proxy_addr"`
	AdminAddr       string        `mapstructure:"admin_addr"`
	MetricsAddr     string        `mapstructure:"metrics_addr"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	MaxConns        int           `mapstructure:"max_conns"`
	MaxRequestBody  int           `mapstructure:"max_request_body"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	TrustedProxies  []string      `mapstructure:"trusted_proxies"`
}

// ProxyConfig задаёт параметры подключения к целевым HTTP-серверам.
type ProxyConfig struct {
	MaxConnsPerHost     int           `mapstructure:"max_conns_per_host"`
	ReadTimeout         time.Duration `mapstructure:"read_timeout"`
	WriteTimeout        time.Duration `mapstructure:"write_timeout"`
	DialTimeout         time.Duration `mapstructure:"dial_timeout"`
	MaxIdleConnDuration time.Duration `mapstructure:"max_idle_conn_duration"`
	DNSCacheTTL         time.Duration `mapstructure:"dns_cache_ttl"`
	DialConcurrency     int           `mapstructure:"dial_concurrency"`
	BufferSize          int           `mapstructure:"buffer_size"`
	AllowPrivateTargets bool          `mapstructure:"allow_private_targets"`
}

// PostgresConfig задаёт параметры пулов PostgreSQL.
type PostgresConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxConns        int32         `mapstructure:"max_conns"`
	MinConns        int32         `mapstructure:"min_conns"`
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time"`
	ReadReplicaDSN  string        `mapstructure:"read_replica_dsn"`
}

// RedisConfig задаёт параметры клиента Redis.
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	PoolSize int    `mapstructure:"pool_size"`
	Enabled  bool   `mapstructure:"enabled"`
}

// AuthConfig задаёт параметры аутентификации (JWT, OAuth2, bootstrap).
type AuthConfig struct {
	JWTSecret           string        `mapstructure:"jwt_secret"`
	JWTIssuer           string        `mapstructure:"jwt_issuer"`
	TokenCacheTTL       time.Duration `mapstructure:"token_cache_ttl"`
	OAuth2Enabled       bool          `mapstructure:"oauth2_enabled"`
	OAuth2IntrospectURL string        `mapstructure:"oauth2_introspect_url"`
	OAuth2JWKSURL       string        `mapstructure:"oauth2_jwks_url"`
	RequireAuthForProxy bool          `mapstructure:"require_auth_for_proxy"`
	// BootstrapToken при наличии разрешает POST /api/v1/auth/token (только для разработки).
	// Запрос должен содержать заголовок X-Bootstrap-Token с этим значением.
	BootstrapToken string `mapstructure:"bootstrap_token"`
}

// CacheConfig задаёт параметры кэширования правил и ответов.
type CacheConfig struct {
	RulesTTL        time.Duration `mapstructure:"rules_ttl"`
	ResponseTTL     time.Duration `mapstructure:"response_ttl"`
	Enabled         bool          `mapstructure:"enabled"`
	ResponseEnabled bool          `mapstructure:"response_enabled"`
}

// QueueConfig задаёт параметры очереди событий.
type QueueConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Backend string `mapstructure:"backend"` // допустимые значения: kafka | none
	Brokers string `mapstructure:"brokers"`
	Topic   string `mapstructure:"topic"`
	// GroupID сохраняет совместимое имя настройки и используется издателем как Kafka client ID.
	GroupID string `mapstructure:"group_id"`
}

// RateLimitConfig задаёт ограничения частоты запросов и числа соединений.
type RateLimitConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	DefaultRPS    int  `mapstructure:"default_rps"`
	Burst         int  `mapstructure:"burst"`
	PerIPLimit    int  `mapstructure:"per_ip_limit"`
	MaxConnsPerIP int  `mapstructure:"max_conns_per_ip"`
}

// LogConfig задаёт формат, уровень и способ хранения журналов.
type LogConfig struct {
	Level           string `mapstructure:"level"`
	Format          string `mapstructure:"format"`           // допустимые значения: json | console
	PersistRequests bool   `mapstructure:"persist_requests"` // синхронная вставка в PG (по умолчанию выключена ради RPS)
}

// LoadOrDefault загружает конфигурацию или возвращает значения по умолчанию, если файл отсутствует.
func LoadOrDefault(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	v.SetEnvPrefix("GUARDIAN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		_ = v.ReadInConfig()
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.proxy_addr", ":8080")
	v.SetDefault("server.admin_addr", ":8081")
	v.SetDefault("server.metrics_addr", ":9090")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.max_conns", 10000)
	v.SetDefault("server.max_request_body", 10<<20)
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("server.trusted_proxies", []string{})

	v.SetDefault("proxy.max_conns_per_host", 1000)
	v.SetDefault("proxy.read_timeout", "30s")
	v.SetDefault("proxy.write_timeout", "30s")
	v.SetDefault("proxy.dial_timeout", "5s")
	v.SetDefault("proxy.max_idle_conn_duration", "30s")
	v.SetDefault("proxy.dns_cache_ttl", "1h")
	v.SetDefault("proxy.dial_concurrency", 4096)
	v.SetDefault("proxy.buffer_size", 32*1024)
	v.SetDefault("proxy.allow_private_targets", false)

	v.SetDefault("postgres.dsn", "postgres://guardian:guardian@localhost:5432/guardian?sslmode=disable")
	v.SetDefault("postgres.max_conns", 50)
	v.SetDefault("postgres.min_conns", 5)
	v.SetDefault("postgres.max_conn_lifetime", "1h")
	v.SetDefault("postgres.max_conn_idle_time", "30m")

	v.SetDefault("redis.enabled", true)
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 100)

	v.SetDefault("auth.jwt_secret", "")
	v.SetDefault("auth.jwt_issuer", "guardian")
	v.SetDefault("auth.token_cache_ttl", "10m")
	v.SetDefault("auth.oauth2_enabled", false)
	v.SetDefault("auth.require_auth_for_proxy", false)
	v.SetDefault("auth.bootstrap_token", "")

	v.SetDefault("cache.enabled", true)
	v.SetDefault("cache.rules_ttl", "30s")
	v.SetDefault("cache.response_ttl", "60s")
	v.SetDefault("cache.response_enabled", false)

	v.SetDefault("queue.enabled", false)
	v.SetDefault("queue.backend", "none")
	v.SetDefault("queue.brokers", "localhost:9092")
	v.SetDefault("queue.topic", "guardian-events")
	v.SetDefault("queue.group_id", "guardian")

	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.default_rps", 1000)
	v.SetDefault("rate_limit.burst", 2000)
	v.SetDefault("rate_limit.per_ip_limit", 500)
	v.SetDefault("rate_limit.max_conns_per_ip", 100)

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.persist_requests", false)
}
