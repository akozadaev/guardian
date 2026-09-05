package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Role представляет роли RBAC.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleModerator Role = "moderator"
	RoleUser      Role = "user"
	RoleGuest     Role = "guest"
)

// Action задаёт действие правила фильтрации.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionBlock  Action = "block"
	ActionModify Action = "modify"
)

// ConditionOperator задаёт оператор составных правил.
type ConditionOperator string

const (
	OpAND ConditionOperator = "AND"
	OpOR  ConditionOperator = "OR"
	OpNOT ConditionOperator = "NOT"
)

// FieldOperator задаёт оператор сопоставления одного условия.
type FieldOperator string

const (
	FieldEq       FieldOperator = "eq"
	FieldNeq      FieldOperator = "neq"
	FieldIn       FieldOperator = "in"
	FieldNotIn    FieldOperator = "not_in"
	FieldContains FieldOperator = "contains"
	FieldPrefix   FieldOperator = "prefix"
	FieldRegex    FieldOperator = "regex"
	FieldGt       FieldOperator = "gt"
	FieldLt       FieldOperator = "lt"
	FieldExists   FieldOperator = "exists"
)

// User представляет пользователя, хранящегося в PostgreSQL.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      Role      `json:"role"`
	Active    bool      `json:"active"`
	QuotaRPS  int       `json:"quota_rps"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RuleResponse представляет HTTP-ответ, возвращаемый при блокировке или изменении запроса.
type RuleResponse struct {
	Status  int               `json:"status"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers,omitempty"`
}

// ConditionNode представляет рекурсивное дерево условий (AND/OR/NOT и листовые правила).
// В соответствии с ТЗ JSON использует "operator" как для составных (AND/OR/NOT), так и для листовых операторов (eq/in/regex).
type ConditionNode struct {
	Operator ConditionOperator `json:"-"`
	Op       FieldOperator     `json:"-"`
	Rules    []ConditionNode   `json:"rules,omitempty"`
	Field    string            `json:"field,omitempty"`
	Value    json.RawMessage   `json:"value,omitempty"`
}

// UnmarshalJSON сопоставляет поле "operator" из ТЗ с составным Operator или листовым Op.
func (c *ConditionNode) UnmarshalJSON(data []byte) error {
	var raw struct {
		Operator string          `json:"operator"`
		Op       string          `json:"op"`
		Rules    []ConditionNode `json:"rules"`
		Field    string          `json:"field"`
		Value    json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Rules = raw.Rules
	c.Field = raw.Field
	c.Value = raw.Value
	op := raw.Operator
	if op == "" {
		op = raw.Op
	}
	if raw.Field != "" {
		c.Op = FieldOperator(op)
	} else {
		c.Operator = ConditionOperator(op)
	}
	return nil
}

// MarshalJSON формирует совместимое с ТЗ поле "operator".
func (c ConditionNode) MarshalJSON() ([]byte, error) {
	raw := map[string]any{}
	if c.Field != "" {
		raw["field"] = c.Field
		if c.Op != "" {
			raw["operator"] = c.Op
		}
		if len(c.Value) > 0 {
			raw["value"] = c.Value
		}
	} else {
		if c.Operator != "" {
			raw["operator"] = c.Operator
		}
		if len(c.Rules) > 0 {
			raw["rules"] = c.Rules
		}
	}
	return json.Marshal(raw)
}

// Rule представляет правило фильтрации.
type Rule struct {
	ID         uuid.UUID     `json:"id"`
	Name       string        `json:"name"`
	Priority   int           `json:"priority"`
	Enabled    bool          `json:"enabled"`
	Conditions ConditionNode `json:"conditions"`
	Action     Action        `json:"action"`
	Response   *RuleResponse `json:"response,omitempty"`
	Modify     *ModifySpec   `json:"modify,omitempty"`
	CreatedBy  *uuid.UUID    `json:"created_by,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

// ModifySpec описывает изменения заголовков и тела запроса или ответа.
type ModifySpec struct {
	AddHeaders    map[string]string `json:"add_headers,omitempty"`
	RemoveHeaders []string          `json:"remove_headers,omitempty"`
	SetHeaders    map[string]string `json:"set_headers,omitempty"`
	BodyReplace   string            `json:"body_replace,omitempty"`
}

// AuditLog хранит записи об административных действиях.
type AuditLog struct {
	ID        uuid.UUID       `json:"id"`
	UserID    *uuid.UUID      `json:"user_id,omitempty"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Details   json.RawMessage `json:"details,omitempty"`
	IP        string          `json:"ip"`
	CreatedAt time.Time       `json:"created_at"`
}

// RequestLog хранит записи о проксированных запросах (асинхронно).
type RequestLog struct {
	ID             uuid.UUID  `json:"id"`
	RequestID      uuid.UUID  `json:"request_id"`
	Method         string     `json:"method"`
	URL            string     `json:"url"`
	StatusCode     int        `json:"status_code"`
	ResponseTimeMs int        `json:"response_time_ms"`
	UserID         *uuid.UUID `json:"user_id,omitempty"`
	RuleID         *uuid.UUID `json:"rule_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// RequestContext обрабатывается механизмом фильтрации.
type RequestContext struct {
	Method      string
	URL         string
	Path        string
	Query       string
	Host        string
	IP          string
	Headers     map[string]string
	Body        []byte
	ContentType string
	BodySize    int
	UserID      string
	Role        string
}

// TokenClaims содержит данные, полученные после проверки JWT.
type TokenClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Role     Role      `json:"role"`
	Active   bool      `json:"active"`
	QuotaRPS int       `json:"quota_rps"`
}

// Stats содержит агрегированную статистику.
type Stats struct {
	TotalRequests   int64            `json:"total_requests"`
	BlockedRequests int64            `json:"blocked_requests"`
	ActiveConns     int64            `json:"active_connections"`
	ActiveTunnels   int64            `json:"active_tunnels"`
	ByMethod        map[string]int64 `json:"by_method"`
	ByStatus        map[string]int64 `json:"by_status"`
}

// Вспомогательные типы для пагинации.
type PageParams struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

func (p PageParams) Offset() int {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit < 1 {
		p.Limit = 20
	}
	if p.Limit > 100 {
		p.Limit = 100
	}
	return (p.Page - 1) * p.Limit
}

type PageResult[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"total_pages"`
}
