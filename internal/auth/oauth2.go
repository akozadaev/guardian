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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2 introspection: %w", err)
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
	role, _ := data["role"].(string)
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
	return &models.TokenClaims{UserID: id, Email: email, Role: models.Role(role), Active: active, QuotaRPS: quota}, nil
}
