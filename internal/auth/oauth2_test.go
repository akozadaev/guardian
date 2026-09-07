package auth

import (
	"context"
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
