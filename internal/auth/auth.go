package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/akozadaev/guardian/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Permission представляет разрешение RBAC.
type Permission string

const (
	PermRulesRead   Permission = "rules:read"
	PermRulesWrite  Permission = "rules:write"
	PermUsersRead   Permission = "users:read"
	PermUsersWrite  Permission = "users:write"
	PermStatsRead   Permission = "stats:read"
	PermProxyAccess Permission = "proxy:access"
)

var rolePermissions = map[models.Role][]Permission{
	models.RoleAdmin: {
		PermRulesRead, PermRulesWrite, PermUsersRead, PermUsersWrite, PermStatsRead, PermProxyAccess,
	},
	models.RoleModerator: {
		PermRulesRead, PermRulesWrite, PermStatsRead, PermProxyAccess,
	},
	models.RoleUser: {
		PermRulesRead, PermStatsRead, PermProxyAccess,
	},
	models.RoleGuest: {
		PermProxyAccess,
	},
}

// HasPermission проверяет разрешения RBAC.
func HasPermission(role models.Role, perm Permission) bool {
	for _, p := range rolePermissions[role] {
		if p == perm {
			return true
		}
	}
	return false
}

// TokenCache абстрагирует кэширование результатов аутентификации (в Redis или памяти).
type TokenCache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// MemoryTokenCache представляет простой кэш с TTL.
type MemoryTokenCache struct {
	mu   sync.RWMutex
	data map[string]cacheEntry
}

type cacheEntry struct {
	val []byte
	exp time.Time
}

func NewMemoryTokenCache() *MemoryTokenCache {
	c := &MemoryTokenCache{data: make(map[string]cacheEntry)}
	go c.janitor()
	return c
}

func (c *MemoryTokenCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.data[key]
	if !ok || time.Now().After(e.exp) {
		return nil, nil
	}
	return e.val, nil
}

func (c *MemoryTokenCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = cacheEntry{val: value, exp: time.Now().Add(ttl)}
	return nil
}

func (c *MemoryTokenCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
	return nil
}

func (c *MemoryTokenCache) janitor() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.data {
			if now.After(e.exp) {
				delete(c.data, k)
			}
		}
		c.mu.Unlock()
	}
}

type limiterEntry struct {
	lim *rate.Limiter
	rps int
}

// Service проверяет JWT и обеспечивает соблюдение RBAC.
type Service struct {
	secret     []byte
	issuer     string
	cache      TokenCache
	cacheTTL   time.Duration
	limiters   sync.Map // ключ -> *limiterEntry
	defaultRPS int
	burst      int
}

func NewService(secret, issuer string, cache TokenCache, cacheTTL time.Duration, defaultRPS, burst int) *Service {
	if cache == nil {
		cache = NewMemoryTokenCache()
	}
	if cacheTTL == 0 {
		cacheTTL = 10 * time.Minute
	}
	if defaultRPS <= 0 {
		defaultRPS = 1000
	}
	if burst <= 0 {
		burst = defaultRPS * 2
	}
	return &Service{
		secret:     []byte(secret),
		issuer:     issuer,
		cache:      cache,
		cacheTTL:   cacheTTL,
		defaultRPS: defaultRPS,
		burst:      burst,
	}
}

type claims struct {
	UserID   string      `json:"user_id"`
	Email    string      `json:"email"`
	Role     models.Role `json:"role"`
	Active   bool        `json:"active"`
	QuotaRPS int         `json:"quota_rps"`
	jwt.RegisteredClaims
}

// IssueToken создаёт JWT (для начальной настройки, если она включена).
func (s *Service) IssueToken(user *models.User, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	c := claims{
		UserID:   user.ID.String(),
		Email:    user.Email,
		Role:     user.Role,
		Active:   user.Active,
		QuotaRPS: user.QuotaRPS,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString(s.secret)
}

// ValidateToken разбирает и проверяет JWT с использованием кэша.
func (s *Service) ValidateToken(ctx context.Context, tokenStr string) (*models.TokenClaims, error) {
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, fmt.Errorf("empty token")
	}

	key := TokenCacheKey(tokenStr)
	if raw, err := s.cache.Get(ctx, key); err == nil && raw != nil {
		var tc models.TokenClaims
		if json.Unmarshal(raw, &tc) == nil {
			if !tc.Active {
				return nil, fmt.Errorf("user inactive")
			}
			if uraw, err := s.cache.Get(ctx, "auth:user:"+tc.UserID.String()); err == nil && uraw != nil {
				var st struct {
					Active bool `json:"active"`
				}
				if json.Unmarshal(uraw, &st) == nil && !st.Active {
					return nil, fmt.Errorf("user inactive")
				}
			}
			return &tc, nil
		}
	}

	parsed, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := parsed.Claims.(*claims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if !c.Active {
		return nil, fmt.Errorf("user inactive")
	}
	uid, err := uuid.Parse(c.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id in token")
	}
	tc := &models.TokenClaims{
		UserID:   uid,
		Email:    c.Email,
		Role:     c.Role,
		Active:   c.Active,
		QuotaRPS: c.QuotaRPS,
	}
	// Учитываем переопределения деактивации, сохранённые при обновлении пользователя.
	if raw, err := s.cache.Get(ctx, "auth:user:"+uid.String()); err == nil && raw != nil {
		var st struct {
			Active bool `json:"active"`
		}
		if json.Unmarshal(raw, &st) == nil && !st.Active {
			return nil, fmt.Errorf("user inactive")
		}
	}
	if raw, err := json.Marshal(tc); err == nil {
		_ = s.cache.Set(ctx, key, raw, s.cacheTTL)
	}
	return tc, nil
}

// InvalidateToken удаляет токен из кэша аутентификации.
func (s *Service) InvalidateToken(ctx context.Context, tokenStr string) error {
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
	tokenStr = strings.TrimSpace(tokenStr)
	return s.cache.Delete(ctx, TokenCacheKey(tokenStr))
}

// InvalidateUserTokens не может перечислить хеши JWT; вызывающая сторона должна сменить секрет или дождаться истечения TTL.
// InvalidateUserCache удаляет синтетический ключ, используемый для хранения переопределений статуса пользователя.
func (s *Service) InvalidateUserCache(ctx context.Context, userID uuid.UUID) error {
	return s.cache.Delete(ctx, "auth:user:"+userID.String())
}

// SetUserActiveCache сохраняет переопределение активности, проверяемое перед выдачей кэшированных токенов (необязательно).
func (s *Service) SetUserActiveCache(ctx context.Context, userID uuid.UUID, active bool, ttl time.Duration) error {
	raw, _ := json.Marshal(map[string]bool{"active": active})
	return s.cache.Set(ctx, "auth:user:"+userID.String(), raw, ttl)
}

// AllowRate сообщает, укладывается ли ключ в ограничения частоты. Пересоздаёт ограничитель при изменении RPS.
func (s *Service) AllowRate(key string, rps int) bool {
	if rps <= 0 {
		rps = s.defaultRPS
	}
	burst := s.burst
	if burst < rps {
		burst = rps
	}
	if v, ok := s.limiters.Load(key); ok {
		e := v.(*limiterEntry)
		if e.rps == rps {
			return e.lim.Allow()
		}
	}
	e := &limiterEntry{lim: rate.NewLimiter(rate.Limit(rps), burst), rps: rps}
	actual, _ := s.limiters.LoadOrStore(key, e)
	ent := actual.(*limiterEntry)
	if ent.rps != rps {
		s.limiters.Store(key, e)
		ent = e
	}
	return ent.lim.Allow()
}

// TokenCacheKey формирует ключ Redis или кэша в памяти для необработанного токена.
func TokenCacheKey(tokenStr string) string {
	return "auth:token:" + hashToken(tokenStr)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// WeakSecret сообщает, является ли настроенный секрет известным небезопасным значением по умолчанию.
func WeakSecret(secret string) bool {
	switch secret {
	case "", "change-me-in-production-guardian-secret-key", "dev-secret-change-me":
		return true
	default:
		return len(secret) < 16
	}
}
