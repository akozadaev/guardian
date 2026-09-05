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
	authTTL  time.Duration
	respTTL  time.Duration
}

func NewStore(rdb *redis.Client, enabled bool, rulesTTL, authTTL, respTTL time.Duration) *Store {
	if rulesTTL == 0 {
		rulesTTL = 30 * time.Second
	}
	if authTTL == 0 {
		authTTL = 10 * time.Minute
	}
	if respTTL == 0 {
		respTTL = 60 * time.Second
	}
	return &Store{
		rdb:      rdb,
		enabled:  enabled && rdb != nil,
		local:    &sync.Map{},
		rulesTTL: rulesTTL,
		authTTL:  authTTL,
		respTTL:  respTTL,
	}
}

func (s *Store) Client() *redis.Client { return s.rdb }

func (s *Store) Ping(ctx context.Context) error {
	if !s.enabled {
		return nil
	}
	return s.rdb.Ping(ctx).Err()
}

// --- Интерфейс auth.TokenCache ---

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

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.local.Store(key, localEntry{val: value, exp: time.Now().Add(ttl)})
	if !s.enabled {
		return nil
	}
	return s.rdb.Set(ctx, key, value, ttl).Err()
}

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

func (s *Store) SetRules(ctx context.Context, rules []models.Rule) error {
	raw, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return s.Set(ctx, "rules:all", raw, s.rulesTTL)
}

func (s *Store) InvalidateRules(ctx context.Context) error {
	return s.Delete(ctx, "rules:all")
}

// Кэш ответов

func responseKey(urlHash string) string {
	return fmt.Sprintf("cache:response:%s", urlHash)
}

func (s *Store) GetResponse(ctx context.Context, urlHash string) ([]byte, bool) {
	raw, err := s.Get(ctx, responseKey(urlHash))
	if err != nil || raw == nil {
		return nil, false
	}
	return raw, true
}

func (s *Store) SetResponse(ctx context.Context, urlHash string, data []byte) error {
	return s.Set(ctx, responseKey(urlHash), data, s.respTTL)
}

// Счётчик ограничения частоты через Redis (необязательный распределённый режим).
func (s *Store) IncrRate(ctx context.Context, key string, window time.Duration) (int64, error) {
	if !s.enabled {
		return 0, fmt.Errorf("redis disabled")
	}
	pipe := s.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
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
