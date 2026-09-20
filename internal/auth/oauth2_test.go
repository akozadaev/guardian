package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/akozadaev/guardian/internal/models"
	"github.com/google/uuid"
)

func TestOAuth2ValidatorIntrospection(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	validator := NewOAuth2Validator("https://idp.example/introspect", "", "guardian")
	validator.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.Form.Get("token"); got != "external-token" {
			t.Errorf("token = %q", got)
		}
		body := `{"active":true,"sub":"` + userID.String() + `","email":"user@example.com","role":"user","quota_rps":42}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})

	claims, err := validator.ValidateToken(context.Background(), "external-token")
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.UserID != userID || claims.Role != models.RoleUser || claims.QuotaRPS != 42 {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestOAuth2ValidatorGoOAuth2ServerCompatibility(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	requests := 0
	validator := NewOAuth2Validator("https://oauth2.example/introspect", "", "")
	validator.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Errorf("first Content-Type = %q", got)
			}
			return oauthResponse(http.StatusBadRequest, `{"error":"invalid_request"}`), nil
		}

		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("fallback Content-Type = %q", got)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode fallback request: %v", err)
		}
		if request["token"] != "oauth-token" || request["token_type_hint"] != "access_token" {
			t.Fatalf("unexpected fallback request: %#v", request)
		}
		body := `{"active":true,"user_id":"` + userID.String() + `","roles":["ROLE_USER","ROLE_EDITOR"]}`
		return oauthResponse(http.StatusOK, body), nil
	})

	claims, err := validator.ValidateToken(context.Background(), "oauth-token")
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if claims.UserID != userID || claims.Role != models.RoleModerator {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestOAuth2RoleMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string]any
		want models.Role
	}{
		{name: "native role", data: map[string]any{"role": "user"}, want: models.RoleUser},
		{name: "oauth admin", data: map[string]any{"roles": []any{"ROLE_USER", "ROLE_ADMIN"}}, want: models.RoleAdmin},
		{name: "oauth super admin", data: map[string]any{"roles": []any{"ROLE_SUPER_ADMIN"}}, want: models.RoleAdmin},
		{name: "oauth editor", data: map[string]any{"roles": []any{"ROLE_EDITOR"}}, want: models.RoleModerator},
		{name: "oauth user", data: map[string]any{"roles": []any{"ROLE_USER"}}, want: models.RoleUser},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := roleFromClaims(tt.data)
			if err != nil {
				t.Fatalf("roleFromClaims: %v", err)
			}
			if got != tt.want {
				t.Fatalf("role = %q, want %q", got, tt.want)
			}
		})
	}
}

func oauthResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInvalidateTokenRevokesToken(t *testing.T) {
	t.Parallel()

	cache := NewMemoryTokenCache()
	service := NewService("strong-test-secret", "guardian", cache, 0, 10, 20)
	user := &models.User{ID: uuid.New(), Email: "user@example.com", Role: models.RoleUser, Active: true, QuotaRPS: 10}
	token, err := service.IssueToken(user, 0)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := service.ValidateToken(context.Background(), token); err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if err := service.InvalidateToken(context.Background(), token); err != nil {
		t.Fatalf("invalidate token: %v", err)
	}
	if _, err := service.ValidateToken(context.Background(), token); err == nil {
		t.Fatal("revoked token was accepted")
	}
}
