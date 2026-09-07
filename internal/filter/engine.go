// Package filter проверяет HTTP-запросы по настроенным правилам фильтрации.
package filter

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/akozadaev/guardian/internal/models"
)

// Result представляет результат проверки запроса по правилам.
type Result struct {
	Matched  bool
	Rule     *models.Rule
	Action   models.Action
	Response *models.RuleResponse
	Modify   *models.ModifySpec
}

// Engine проверяет правила фильтрации с использованием кэша в памяти.
type Engine struct {
	mu      sync.RWMutex
	rules   []models.Rule
	reCache sync.Map // строка -> *regexp.Regexp
}

// NewEngine создаёт движок фильтрации без правил.
func NewEngine() *Engine {
	return &Engine{rules: make([]models.Rule, 0)}
}

// SetRules заменяет активный набор правил (сортировка по убыванию приоритета).
func (e *Engine) SetRules(rules []models.Rule) {
	sorted := make([]models.Rule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})
	e.mu.Lock()
	e.rules = sorted
	e.mu.Unlock()
}

// Evaluate применяет включённые правила в порядке приоритета; используется первое совпадение.
func (e *Engine) Evaluate(ctx *models.RequestContext) Result {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		ok, err := e.matchNode(&r.Conditions, ctx)
		if err != nil || !ok {
			continue
		}
		ruleCopy := *r
		return Result{
			Matched:  true,
			Rule:     &ruleCopy,
			Action:   r.Action,
			Response: r.Response,
			Modify:   r.Modify,
		}
	}
	return Result{Matched: false, Action: models.ActionAllow}
}

// TestRule изолированно проверяет одно правило в заданном контексте.
func (e *Engine) TestRule(rule *models.Rule, ctx *models.RequestContext) (bool, error) {
	return e.matchNode(&rule.Conditions, ctx)
}

func (e *Engine) matchNode(node *models.ConditionNode, ctx *models.RequestContext) (bool, error) {
	if node == nil {
		return true, nil
	}

	// Листовое условие.
	if node.Field != "" {
		return e.matchLeaf(node, ctx)
	}

	switch node.Operator {
	case models.OpAND, "":
		if len(node.Rules) == 0 {
			return false, nil
		}
		for i := range node.Rules {
			ok, err := e.matchNode(&node.Rules[i], ctx)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case models.OpOR:
		if len(node.Rules) == 0 {
			return false, nil
		}
		for i := range node.Rules {
			ok, err := e.matchNode(&node.Rules[i], ctx)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case models.OpNOT:
		if len(node.Rules) == 0 {
			return false, nil
		}
		ok, err := e.matchNode(&node.Rules[0], ctx)
		if err != nil {
			return false, err
		}
		return !ok, nil
	default:
		return false, fmt.Errorf("unknown operator: %s", node.Operator)
	}
}

func (e *Engine) matchLeaf(node *models.ConditionNode, ctx *models.RequestContext) (bool, error) {
	fieldVal := fieldValue(node.Field, ctx)
	op := node.Op
	if op == "" {
		op = models.FieldEq
	}

	switch op {
	case models.FieldExists:
		return fieldVal != "", nil
	case models.FieldEq:
		want, err := decodeString(node.Value)
		return fieldVal == want, err
	case models.FieldNeq:
		want, err := decodeString(node.Value)
		return fieldVal != want, err
	case models.FieldContains:
		want, err := decodeString(node.Value)
		return strings.Contains(fieldVal, want), err
	case models.FieldPrefix:
		want, err := decodeString(node.Value)
		return strings.HasPrefix(fieldVal, want), err
	case models.FieldIn:
		list, err := decodeStringSlice(node.Value)
		if err != nil {
			return false, err
		}
		if node.Field == "ip" {
			return ipInList(fieldVal, list), nil
		}
		for _, v := range list {
			if strings.EqualFold(fieldVal, v) {
				return true, nil
			}
		}
		return false, nil
	case models.FieldNotIn:
		list, err := decodeStringSlice(node.Value)
		if err != nil {
			return false, err
		}
		if node.Field == "ip" {
			return !ipInList(fieldVal, list), nil
		}
		for _, v := range list {
			if strings.EqualFold(fieldVal, v) {
				return false, nil
			}
		}
		return true, nil
	case models.FieldRegex:
		pat, err := decodeString(node.Value)
		if err != nil {
			return false, err
		}
		re, err := e.getRegexp(pat)
		if err != nil {
			return false, err
		}
		return re.MatchString(fieldVal), nil
	case models.FieldGt:
		n, err := strconv.ParseInt(fieldVal, 10, 64)
		if err != nil {
			return false, nil
		}
		want, err := decodeInt(node.Value)
		return n > want, err
	case models.FieldLt:
		n, err := strconv.ParseInt(fieldVal, 10, 64)
		if err != nil {
			return false, nil
		}
		want, err := decodeInt(node.Value)
		return n < want, err
	default:
		return false, fmt.Errorf("unknown field operator: %s", op)
	}
}

func (e *Engine) getRegexp(pat string) (*regexp.Regexp, error) {
	if v, ok := e.reCache.Load(pat); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	e.reCache.Store(pat, re)
	return re, nil
}

func fieldValue(field string, ctx *models.RequestContext) string {
	switch strings.ToLower(field) {
	case "method":
		return ctx.Method
	case "url":
		return ctx.URL
	case "path":
		return ctx.Path
	case "query":
		return ctx.Query
	case "host":
		return ctx.Host
	case "ip":
		return ctx.IP
	case "content_type", "content-type":
		return ctx.ContentType
	case "body_size":
		return strconv.Itoa(ctx.BodySize)
	case "body":
		return string(ctx.Body)
	case "user_id":
		return ctx.UserID
	case "role":
		return ctx.Role
	default:
		if strings.HasPrefix(field, "header.") {
			key := strings.TrimPrefix(field, "header.")
			if ctx.Headers != nil {
				// Поиск заголовка без учёта регистра.
				for k, v := range ctx.Headers {
					if strings.EqualFold(k, key) {
						return v
					}
				}
			}
		}
		return ""
	}
}

func ipInList(ip string, list []string) bool {
	parsed := net.ParseIP(ip)
	for _, item := range list {
		if strings.Contains(item, "/") {
			_, cidr, err := net.ParseCIDR(item)
			if err == nil && parsed != nil && cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if ip == item {
			return true
		}
	}
	return false
}

func decodeString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String(), nil
	}
	return strings.Trim(string(raw), `"`), nil
}

func decodeStringSlice(raw json.RawMessage) ([]string, error) {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	s, err := decodeString(raw)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

func decodeInt(raw json.RawMessage) (int64, error) {
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	s, err := decodeString(raw)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}

// ValidateRule проверяет синтаксис правила.
func ValidateRule(rule *models.Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch rule.Action {
	case models.ActionAllow, models.ActionBlock, models.ActionModify:
	default:
		return fmt.Errorf("invalid action: %s", rule.Action)
	}
	if rule.Action == models.ActionBlock && rule.Response == nil {
		rule.Response = &models.RuleResponse{Status: 403, Body: "Access denied"}
	}
	if err := validateNode(&rule.Conditions, 0); err != nil {
		return err
	}
	return nil
}

const maxConditionDepth = 32

func validateNode(node *models.ConditionNode, depth int) error {
	if node == nil {
		return fmt.Errorf("conditions required")
	}
	if depth > maxConditionDepth {
		return fmt.Errorf("condition tree too deep")
	}
	if node.Field != "" {
		if node.Op == "" {
			return fmt.Errorf("field %q requires operator", node.Field)
		}
		if node.Op == models.FieldRegex {
			pat, err := decodeString(node.Value)
			if err != nil {
				return err
			}
			if _, err := regexp.Compile(pat); err != nil {
				return fmt.Errorf("invalid regex: %w", err)
			}
		}
		return nil
	}
	switch node.Operator {
	case models.OpAND, models.OpOR:
		if len(node.Rules) == 0 {
			return fmt.Errorf("%s condition requires at least one child rule", node.Operator)
		}
	case models.OpNOT:
		if len(node.Rules) != 1 {
			return fmt.Errorf("NOT condition requires exactly one child rule")
		}
	case "":
		return fmt.Errorf("composite condition requires operator AND/OR/NOT or a field")
	default:
		return fmt.Errorf("unknown operator: %s", node.Operator)
	}
	for i := range node.Rules {
		if err := validateNode(&node.Rules[i], depth+1); err != nil {
			return err
		}
	}
	return nil
}
