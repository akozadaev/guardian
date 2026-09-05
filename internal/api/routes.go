package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/akozadaev/guardian/internal/models"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

//go:generate go run ../../cmd/openapi -output ../../docs/openapi.yaml

// RouteParameter описывает параметр маршрута для OpenAPI.
type RouteParameter struct {
	Name        string
	In          string
	Description string
	Required    bool
	Type        string
	Format      string
}

// RouteResponse описывает один из ответов маршрута.
type RouteResponse struct {
	Status      int
	Description string
	Body        any
}

// Route содержит метаданные маршрута, используемые маршрутизатором и генератором OpenAPI.
type Route struct {
	Method      string
	Path        string
	Summary     string
	Description string
	Security    bool
	Parameters  []RouteParameter
	RequestBody any
	Responses   []RouteResponse
	handler     func(*Handler, *fasthttp.RequestCtx)
}

// TokenRequest представляет запрос на выпуск JWT.
type TokenRequest struct {
	Email string `json:"email" required:"true"`
}

// TokenResponse представляет успешно выпущенный JWT.
type TokenResponse struct {
	AccessToken string `json:"access_token" required:"true"`
	TokenType   string `json:"token_type" required:"true"`
}

// StatusResponse представляет ответ проверки состояния сервиса.
type StatusResponse struct {
	Status string `json:"status" required:"true"`
}

// ErrorResponse представляет ошибку API.
type ErrorResponse struct {
	Error string `json:"error" required:"true"`
}

// RuleTestResponse представляет результат проверки правила.
type RuleTestResponse struct {
	Matched bool   `json:"matched" required:"true"`
	Action  string `json:"action" required:"true" enum:"allow,block,modify"`
}

// ConditionNodeSchema описывает фактическое JSON-представление условия правила.
type ConditionNodeSchema struct {
	Operator string                `json:"operator" required:"true" enum:"AND,OR,NOT,eq,neq,in,not_in,contains,prefix,regex,gt,lt,exists"`
	Rules    []ConditionNodeSchema `json:"rules,omitempty"`
	Field    string                `json:"field,omitempty"`
	Value    any                   `json:"value,omitempty"`
}

// RuleSchema описывает JSON-представление правила для OpenAPI.
type RuleSchema struct {
	ID         uuid.UUID            `json:"id" format:"uuid"`
	Name       string               `json:"name" required:"true"`
	Priority   int                  `json:"priority" required:"true"`
	Enabled    bool                 `json:"enabled" required:"true"`
	Conditions ConditionNodeSchema  `json:"conditions" required:"true"`
	Action     string               `json:"action" required:"true" enum:"allow,block,modify"`
	Response   *models.RuleResponse `json:"response,omitempty"`
	Modify     *models.ModifySpec   `json:"modify,omitempty"`
	CreatedBy  *uuid.UUID           `json:"created_by,omitempty" format:"uuid"`
	CreatedAt  time.Time            `json:"created_at" format:"date-time"`
	UpdatedAt  time.Time            `json:"updated_at" format:"date-time"`
}

// RulePageResponse описывает страницу правил.
type RulePageResponse struct {
	Items      []RuleSchema `json:"items" required:"true"`
	Total      int64        `json:"total" required:"true"`
	Page       int          `json:"page" required:"true"`
	Limit      int          `json:"limit" required:"true"`
	TotalPages int          `json:"total_pages" required:"true"`
}

// RuleStat представляет статистику применения правила.
type RuleStat struct {
	RuleID string  `json:"rule_id" required:"true"`
	Hits   int64   `json:"hits" required:"true"`
	AvgMS  float64 `json:"avg_ms" required:"true"`
}

// UserStat представляет статистику запросов пользователя.
type UserStat struct {
	UserID   string  `json:"user_id" required:"true"`
	Requests int64   `json:"requests" required:"true"`
	AvgMS    float64 `json:"avg_ms" required:"true"`
}

var idParameter = RouteParameter{
	Name:     "id",
	In:       "path",
	Required: true,
	Type:     "string",
	Format:   "uuid",
}

var errorBody = ErrorResponse{}

var adminRoutes = []Route{
	{
		Method: http.MethodGet, Path: "/health", Summary: "Проверка работоспособности",
		Responses: []RouteResponse{{Status: 200, Description: "Сервис работает", Body: StatusResponse{}}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.health(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/ready", Summary: "Проверка готовности",
		Responses: []RouteResponse{
			{Status: 200, Description: "Сервис готов", Body: StatusResponse{}},
			{Status: 503, Description: "Сервис не готов", Body: errorBody},
		},
		handler: func(h *Handler, ctx *fasthttp.RequestCtx) { h.readiness(ctx) },
	},
	{
		Method: http.MethodPost, Path: "/api/v1/auth/token", Summary: "Выпуск JWT для разработки",
		Description: "Доступен только при настроенном auth.bootstrap_token.",
		Parameters:  []RouteParameter{{Name: "X-Bootstrap-Token", In: "header", Required: true, Type: "string"}},
		RequestBody: TokenRequest{},
		Responses: []RouteResponse{
			{Status: 200, Description: "Токен выпущен", Body: TokenResponse{}},
			{Status: 400, Description: "Некорректный запрос", Body: errorBody},
			{Status: 401, Description: "Некорректный bootstrap-токен", Body: errorBody},
			{Status: 403, Description: "Пользователь неактивен", Body: errorBody},
			{Status: 404, Description: "Начальная настройка отключена или пользователь не найден", Body: errorBody},
		},
		handler: func(h *Handler, ctx *fasthttp.RequestCtx) { h.issueDevToken(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/rules", Summary: "Список правил", Security: true,
		Parameters: []RouteParameter{
			{Name: "page", In: "query", Type: "integer"},
			{Name: "limit", In: "query", Type: "integer"},
		},
		Responses: []RouteResponse{{Status: 200, Description: "Страница правил", Body: RulePageResponse{}}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.listRules(ctx) },
	},
	{
		Method: http.MethodPost, Path: "/api/v1/rules", Summary: "Создание правила", Security: true,
		RequestBody: RuleSchema{},
		Responses:   []RouteResponse{{Status: 201, Description: "Правило создано", Body: RuleSchema{}}},
		handler:     func(h *Handler, ctx *fasthttp.RequestCtx) { h.createRule(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/rules/{id}", Summary: "Получение правила", Security: true,
		Parameters: []RouteParameter{idParameter},
		Responses:  []RouteResponse{{Status: 200, Description: "Правило", Body: RuleSchema{}}, {Status: 404, Description: "Правило не найдено", Body: errorBody}},
		handler:    func(h *Handler, ctx *fasthttp.RequestCtx) { h.getRule(ctx) },
	},
	{
		Method: http.MethodPut, Path: "/api/v1/rules/{id}", Summary: "Изменение правила", Security: true,
		Parameters: []RouteParameter{idParameter}, RequestBody: RuleSchema{},
		Responses: []RouteResponse{{Status: 200, Description: "Правило изменено", Body: RuleSchema{}}, {Status: 404, Description: "Правило не найдено", Body: errorBody}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.updateRule(ctx) },
	},
	{
		Method: http.MethodDelete, Path: "/api/v1/rules/{id}", Summary: "Удаление правила", Security: true,
		Parameters: []RouteParameter{idParameter},
		Responses:  []RouteResponse{{Status: 204, Description: "Правило удалено"}, {Status: 404, Description: "Правило не найдено", Body: errorBody}},
		handler:    func(h *Handler, ctx *fasthttp.RequestCtx) { h.deleteRule(ctx) },
	},
	{
		Method: http.MethodPost, Path: "/api/v1/rules/{id}/test", Summary: "Проверка правила", Security: true,
		Parameters: []RouteParameter{idParameter}, RequestBody: models.RequestContext{},
		Responses: []RouteResponse{{Status: 200, Description: "Результат проверки", Body: RuleTestResponse{}}, {Status: 404, Description: "Правило не найдено", Body: errorBody}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.testRule(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/users", Summary: "Список пользователей", Security: true,
		Parameters: []RouteParameter{{Name: "page", In: "query", Type: "integer"}, {Name: "limit", In: "query", Type: "integer"}},
		Responses:  []RouteResponse{{Status: 200, Description: "Страница пользователей", Body: models.PageResult[models.User]{}}},
		handler:    func(h *Handler, ctx *fasthttp.RequestCtx) { h.listUsers(ctx) },
	},
	{
		Method: http.MethodPost, Path: "/api/v1/users", Summary: "Создание пользователя", Security: true,
		RequestBody: models.User{}, Responses: []RouteResponse{{Status: 201, Description: "Пользователь создан", Body: models.User{}}},
		handler: func(h *Handler, ctx *fasthttp.RequestCtx) { h.createUser(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/users/{id}", Summary: "Получение пользователя", Security: true,
		Parameters: []RouteParameter{idParameter},
		Responses:  []RouteResponse{{Status: 200, Description: "Пользователь", Body: models.User{}}, {Status: 404, Description: "Пользователь не найден", Body: errorBody}},
		handler:    func(h *Handler, ctx *fasthttp.RequestCtx) { h.getUser(ctx) },
	},
	{
		Method: http.MethodPut, Path: "/api/v1/users/{id}", Summary: "Изменение пользователя", Security: true,
		Parameters: []RouteParameter{idParameter}, RequestBody: models.User{},
		Responses: []RouteResponse{{Status: 200, Description: "Пользователь изменён", Body: models.User{}}, {Status: 404, Description: "Пользователь не найден", Body: errorBody}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.updateUser(ctx) },
	},
	{
		Method: http.MethodDelete, Path: "/api/v1/users/{id}", Summary: "Удаление пользователя", Security: true,
		Parameters: []RouteParameter{idParameter},
		Responses:  []RouteResponse{{Status: 204, Description: "Пользователь удалён"}, {Status: 404, Description: "Пользователь не найден", Body: errorBody}},
		handler:    func(h *Handler, ctx *fasthttp.RequestCtx) { h.deleteUser(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/stats", Summary: "Общая статистика", Security: true,
		Responses: []RouteResponse{{Status: 200, Description: "Статистика", Body: models.Stats{}}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.stats(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/stats/rules", Summary: "Статистика по правилам", Security: true,
		Responses: []RouteResponse{{Status: 200, Description: "Статистика по правилам", Body: []RuleStat{}}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.statsRules(ctx) },
	},
	{
		Method: http.MethodGet, Path: "/api/v1/stats/users", Summary: "Статистика по пользователям", Security: true,
		Responses: []RouteResponse{{Status: 200, Description: "Статистика по пользователям", Body: []UserStat{}}},
		handler:   func(h *Handler, ctx *fasthttp.RequestCtx) { h.statsUsers(ctx) },
	},
}

// AdminRoutes возвращает единый реестр маршрутов административного API.
func AdminRoutes() []Route { return adminRoutes }

func routeMatches(template, path string) bool {
	want := strings.Split(strings.Trim(template, "/"), "/")
	got := strings.Split(strings.Trim(path, "/"), "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if strings.HasPrefix(want[i], "{") && strings.HasSuffix(want[i], "}") {
			if got[i] == "" {
				return false
			}
			continue
		}
		if want[i] != got[i] {
			return false
		}
	}
	return true
}
