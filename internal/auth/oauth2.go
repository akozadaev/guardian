package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akozadaev/guardian/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// OAuth2Validator проверяет opaque-токены через introspection или JWT через JWKS.
type OAuth2Validator struct {
	introspectURL string
	jwksURL       string
	issuer        string
	client        *http.Client
	mu            sync.RWMutex
	keys          map[string]any
	keysExpires   time.Time
}

// NewOAuth2Validator создаёт валидатор внешних OAuth2-токенов.
func NewOAuth2Validator(introspectURL, jwksURL, issuer string) *OAuth2Validator {
	return &OAuth2Validator{
		introspectURL: introspectURL,
		jwksURL:       jwksURL,
		issuer:        issuer,
		client:        &http.Client{Timeout: 5 * time.Second},
	}
}

// ValidateToken проверяет токен выбранным настроенным способом.
func (v *OAuth2Validator) ValidateToken(ctx context.Context, token string) (*models.TokenClaims, error) {
	if v.jwksURL != "" {
		return v.validateJWKS(ctx, token)
	}
	if v.introspectURL != "" {
		return v.introspect(ctx, token)
	}
	return nil, fmt.Errorf("oauth2 enabled without introspection or JWKS URL")
}

func (v *OAuth2Validator) introspect(ctx context.Context, token string) (*models.TokenClaims, error) {
	form := url.Values{"token": {token}}
	resp, err := v.doIntrospection(ctx, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return nil, fmt.Errorf("oauth2 introspection: %w", err)
	}

	// RFC 7662 использует application/x-www-form-urlencoded. go_oauth2_server
	// принимает JSON, поэтому повторяем только запросы, которые он отверг как
	// неподдерживаемый формат, не скрывая ошибки авторизации и сервера.
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnsupportedMediaType {
		_ = resp.Body.Close()
		body, marshalErr := json.Marshal(map[string]string{
			"token":           token,
			"token_type_hint": "access_token",
		})
		if marshalErr != nil {
			return nil, fmt.Errorf("encode JSON introspection request: %w", marshalErr)
		}
		resp, err = v.doIntrospection(ctx, strings.NewReader(string(body)), "application/json")
		if err != nil {
			return nil, fmt.Errorf("oauth2 JSON introspection: %w", err)
		}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth2 introspection returned %s", resp.Status)
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode introspection response: %w", err)
	}
	if active, _ := data["active"].(bool); !active {
		return nil, fmt.Errorf("inactive token")
	}
	return tokenClaimsFromMap(data)
}

func (v *OAuth2Validator) doIntrospection(ctx context.Context, body *strings.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return v.client.Do(req)
}

func (v *OAuth2Validator) validateJWKS(ctx context.Context, token string) (*models.TokenClaims, error) {
	options := []jwt.ParserOption{}
	if v.issuer != "" {
		options = append(options, jwt.WithIssuer(v.issuer))
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unsupported JWKS signing method %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("JWT kid is missing")
		}
		return v.key(ctx, kid)
	}, options...)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("validate OAuth2 JWT: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected OAuth2 JWT claims")
	}
	return tokenClaimsFromMap(claims)
}

func (v *OAuth2Validator) key(ctx context.Context, kid string) (any, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fresh := time.Now().Before(v.keysExpires)
	v.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok = v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("JWKS key %q not found", kid)
	}
	return key, nil
}

func (v *OAuth2Validator) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned %s", resp.Status)
	}
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]any, len(set.Keys))
	for _, item := range set.Keys {
		if item.KTY != "RSA" || item.KID == "" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(item.N)
		if err != nil {
			return fmt.Errorf("decode JWKS modulus: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(item.E)
		if err != nil {
			return fmt.Errorf("decode JWKS exponent: %w", err)
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		keys[item.KID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	v.mu.Lock()
	v.keys = keys
	v.keysExpires = time.Now().Add(5 * time.Minute)
	v.mu.Unlock()
	return nil
}

func tokenClaimsFromMap(data map[string]any) (*models.TokenClaims, error) {
	userID, _ := data["user_id"].(string)
	if userID == "" {
		userID, _ = data["sub"].(string)
	}
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id in OAuth2 token")
	}
	email, _ := data["email"].(string)
	role, err := roleFromClaims(data)
	if err != nil {
		return nil, err
	}
	active := true
	if value, ok := data["active"].(bool); ok {
		active = value
	}
	if !active {
		return nil, fmt.Errorf("inactive token")
	}
	quota := 0
	if value, ok := data["quota_rps"].(float64); ok {
		quota = int(value)
	}
	return &models.TokenClaims{UserID: id, Email: email, Role: role, Active: active, QuotaRPS: quota}, nil
}

func roleFromClaims(data map[string]any) (models.Role, error) {
	if value, ok := data["role"].(string); ok && value != "" {
		if role, ok := guardianRole(value); ok {
			return role, nil
		}
	}

	// go_oauth2_server возвращает роли в массиве roles. Выбираем наиболее
	// привилегированную известную роль независимо от порядка элементов.
	best := models.Role("")
	bestRank := 0
	for _, value := range stringSliceClaim(data["roles"]) {
		role, ok := guardianRole(value)
		if !ok {
			continue
		}
		rank := roleRank(role)
		if rank > bestRank {
			best, bestRank = role, rank
		}
	}
	if best == "" {
		return "", fmt.Errorf("OAuth2 token has no recognized Guardian role")
	}
	return best, nil
}

func guardianRole(value string) (models.Role, bool) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ADMIN", "ROLE_ADMIN", "ROLE_SUPER_ADMIN":
		return models.RoleAdmin, true
	case "MODERATOR", "ROLE_EDITOR":
		return models.RoleModerator, true
	case "USER", "ROLE_USER":
		return models.RoleUser, true
	case "GUEST", "ROLE_GUEST":
		return models.RoleGuest, true
	default:
		return "", false
	}
}

func stringSliceClaim(value any) []string {
	switch values := value.(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, item := range values {
			if value, ok := item.(string); ok {
				out = append(out, value)
			}
		}
		return out
	default:
		return nil
	}
}

func roleRank(role models.Role) int {
	switch role {
	case models.RoleAdmin:
		return 4
	case models.RoleModerator:
		return 3
	case models.RoleUser:
		return 2
	case models.RoleGuest:
		return 1
	default:
		return 0
	}
}
