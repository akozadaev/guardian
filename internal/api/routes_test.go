package api

import (
	"net/http"
	"testing"
)

func TestAdminRoutesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, route := range AdminRoutes() {
		key := route.Method + " " + route.Path
		if seen[key] {
			t.Fatalf("повторяющийся маршрут %s", key)
		}
		seen[key] = true
		if route.handler == nil {
			t.Errorf("у маршрута %s отсутствует обработчик", key)
		}
		if len(route.Responses) == 0 {
			t.Errorf("у маршрута %s отсутствуют ответы", key)
		}
	}
}

func TestRouteMatches(t *testing.T) {
	tests := []struct {
		template string
		path     string
		want     bool
	}{
		{"/api/v1/rules", "/api/v1/rules", true},
		{"/api/v1/rules/{id}", "/api/v1/rules/123", true},
		{"/api/v1/rules/{id}", "/api/v1/rules/123/test", false},
		{"/api/v1/rules/{id}/test", "/api/v1/rules/123/test", true},
		{"/api/v1/rules/{id}", "/api/v1/users/123", false},
	}
	for _, test := range tests {
		if got := routeMatches(test.template, test.path); got != test.want {
			t.Errorf("routeMatches(%q, %q) = %v, требуется %v", test.template, test.path, got, test.want)
		}
	}
}

func TestDocumentedRouteCanBeFound(t *testing.T) {
	for _, route := range AdminRoutes() {
		if route.Method == http.MethodPost && routeMatches(route.Path, "/api/v1/rules/123/test") {
			return
		}
	}
	t.Fatal("маршрут проверки правила не найден")
}
