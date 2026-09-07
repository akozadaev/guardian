// Package cache предоставляет локальное и Redis-кэширование данных Guardian.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/akozadaev/guardian/internal/models"
	"github.com/redis/go-redis/v9"
)

// Store объединяет кэширование правил, аутентификации и ответов в Redis и памяти.
type Store struct {
	rdb      *redis.Client
	enabled  bool
	local    *sync.Map
	rulesTTL time.Duration
	respTTL  time.Duration
}

// NewStore создаёт хранилище с локальным in-memory кэшем и опциональным Redis.
func NewStore(rdb *redis.Client, enabled bool, rulesTTL, respTTL time.Duration) *Store {
	if rulesTTL == 0 {
		rulesTTL = 30 * time.Second
	}
	if respTTL == 0 {
		respTTL = 60 * time.Second
	}
	return &Store{
		rdb:      rdb,
		enabled:  enabled && rdb != nil,
		local:    &sync.Map{},
		rulesTTL: rulesTTL,
		respTTL:  respTTL,
	}
}

// Ping проверяет доступность Redis, если он включён.
func (s *Store) Ping(ctx context.Context) error {
	if !s.enabled {
		return nil
	}
	return s.rdb.Ping(ctx).Err()
}

// --- Интерфейс auth.TokenCache ---

// Get возвращает значение из локального кэша или Redis.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	if v, ok := s.local.Load(key); ok {
		e := v.(localEntry)
		if time.Now().Before(e.exp) {
			return e.val, nil
		}
		s.local.Delete(key)
	}
	if !s.enabled {
		return nil, nil
	}
	val, err := s.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return val, err
}

// Set сохраняет значение в локальном кэше и, если он включён, в Redis.
func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.local.Store(key, localEntry{val: value, exp: time.Now().Add(ttl)})
	if !s.enabled {
		return nil
	}
	return s.rdb.Set(ctx, key, value, ttl).Err()
}

// Delete удаляет значение из локального кэша и Redis.
func (s *Store) Delete(ctx context.Context, key string) error {
	s.local.Delete(key)
	if !s.enabled {
		return nil
	}
	return s.rdb.Del(ctx, key).Err()
}

type localEntry struct {
	val []byte
	exp time.Time
}

// Кэш правил

// GetRules возвращает закэшированный набор правил.
func (s *Store) GetRules(ctx context.Context) ([]models.Rule, bool) {
	raw, err := s.Get(ctx, "rules:all")
	if err != nil || raw == nil {
		return nil, false
	}
	var rules []models.Rule
	if json.Unmarshal(raw, &rules) != nil {
		return nil, false
	}
	return rules, true
}

// SetRules сохраняет набор правил в кэше.
func (s *Store) SetRules(ctx context.Context, rules []models.Rule) error {
	raw, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return s.Set(ctx, "rules:all", raw, s.rulesTTL)
}

// InvalidateRules удаляет набор правил из кэша.
func (s *Store) InvalidateRules(ctx context.Context) error {
	return s.Delete(ctx, "rules:all")
}

// Кэш ответов

func responseKey(urlHash string) string {
	return fmt.Sprintf("cache:response:%s", urlHash)
}

// GetResponse возвращает закэшированный HTTP-ответ.
func (s *Store) GetResponse(ctx context.Context, urlHash string) ([]byte, bool) {
	raw, err := s.Get(ctx, responseKey(urlHash))
	if err != nil || raw == nil {
		return nil, false
	}
	return raw, true
}

// SetResponse сохраняет HTTP-ответ в кэше.
func (s *Store) SetResponse(ctx context.Context, urlHash string, data []byte) error {
	return s.Set(ctx, responseKey(urlHash), data, s.respTTL)
}

// IncrRate увеличивает счётчик ограничения частоты в Redis.
func (s *Store) IncrRate(ctx context.Context, key string, window time.Duration) (int64, error) {
	if !s.enabled {
		return 0, fmt.Errorf("redis disabled")
	}
	const script = `
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count`
	return s.rdb.Eval(ctx, script, []string{key}, window.Milliseconds()).Int64()
}

// NewRedisClient создаёт клиент go-redis.
func NewRedisClient(addr, password string, db, poolSize int) *redis.Client {
	if poolSize <= 0 {
		poolSize = 100
	}
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
		PoolSize: poolSize,
	})
}
