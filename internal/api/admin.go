package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/akozadaev/guardian/internal/auth"
	"github.com/akozadaev/guardian/internal/cache"
	"github.com/akozadaev/guardian/internal/filter"
	"github.com/akozadaev/guardian/internal/metrics"
	"github.com/akozadaev/guardian/internal/models"
	"github.com/akozadaev/guardian/internal/netutil"
	"github.com/akozadaev/guardian/internal/proxy"
	"github.com/akozadaev/guardian/internal/queue"
	"github.com/akozadaev/guardian/internal/ratelimit"
	"github.com/akozadaev/guardian/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// Handler обслуживает административный REST API и маршрутизирует трафик прокси-сервера.
type Handler struct {
	Repo               *repository.Store
	Auth               *auth.Service
	Filter             *filter.Engine
	Cache              *cache.Store
	Proxy              *proxy.Core
	Metrics            *metrics.Collector
	Queue              queue.Publisher
	Log                *zap.Logger
	Ready              func() bool
	RequireProxyAuth   bool
	RateLimitEnabled   bool
	PerIPLimit         int
	MaxBody            int
	TrustedProxies     []netip.Prefix
	BootstrapToken     string
	ConnTracker        *ratelimit.ConnTracker
	ResponseCacheOn    bool
	PersistRequestLogs bool
}

func writeJSON(ctx *fasthttp.RequestCtx, status int, v any) {
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	_ = json.NewEncoder(ctx).Encode(v)
}

func writeErr(ctx *fasthttp.RequestCtx, status int, msg string) {
	writeJSON(ctx, status, map[string]string{"error": msg})
}

func (h *Handler) clientIP(ctx *fasthttp.RequestCtx) string {
	return netutil.ClientIP(
		ctx.RemoteAddr().String(),
		string(ctx.Request.Header.Peek("X-Forwarded-For")),
		string(ctx.Request.Header.Peek("X-Real-IP")),
		h.TrustedProxies,
	)
}

func (h *Handler) authUser(ctx *fasthttp.RequestCtx) (*models.TokenClaims, error) {
	authz := string(ctx.Request.Header.Peek("Authorization"))
	if authz == "" {
		return nil, errors.New("missing authorization")
	}
	return h.Auth.ValidateToken(context.Background(), authz)
}

func (h *Handler) requirePerm(ctx *fasthttp.RequestCtx, perm auth.Permission) *models.TokenClaims {
	tc, err := h.authUser(ctx)
	if err != nil {
		writeErr(ctx, fasthttp.StatusUnauthorized, "unauthorized")
		return nil
	}
	if !auth.HasPermission(tc.Role, perm) {
		writeErr(ctx, fasthttp.StatusForbidden, "forbidden")
		return nil
	}
	return tc
}

func (h *Handler) audit(tc *models.TokenClaims, action, resource, ip string, details any) {
	var raw json.RawMessage
	if details != nil {
		raw, _ = json.Marshal(details)
	}
	var uid *uuid.UUID
	if tc != nil {
		id := tc.UserID
		uid = &id
	}
	a := &models.AuditLog{
		ID: uuid.New(), UserID: uid, Action: action, Resource: resource, Details: raw, IP: ip, CreatedAt: time.Now().UTC(),
	}
	go func() {
		_ = h.Repo.InsertAudit(context.Background(), a)
		_ = h.Queue.PublishAudit(context.Background(), a)
	}()
}

// AdminRouter обрабатывает /api/v1/*, /health и /ready на административном порту.
func (h *Handler) AdminRouter(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())
	method := string(ctx.Method())

	switch {
	case path == "/health":
		writeJSON(ctx, 200, map[string]string{"status": "ok"})
		return
	case path == "/ready":
		if h.Ready != nil && !h.Ready() {
			writeErr(ctx, 503, "not ready")
			return
		}
		writeJSON(ctx, 200, map[string]string{"status": "ready"})
		return
	case path == "/api/v1/auth/token" && method == fasthttp.MethodPost:
		h.issueDevToken(ctx)
		return
	}

	if len(path) < 8 || path[:8] != "/api/v1/" {
		writeErr(ctx, 404, "not found")
		return
	}

	switch {
	case path == "/api/v1/rules" && method == fasthttp.MethodGet:
		h.listRules(ctx)
	case path == "/api/v1/rules" && method == fasthttp.MethodPost:
		h.createRule(ctx)
	case startsWith(path, "/api/v1/rules/") && endsWith(path, "/test") && method == fasthttp.MethodPost:
		h.testRule(ctx)
	case startsWith(path, "/api/v1/rules/") && method == fasthttp.MethodGet:
		h.getRule(ctx)
	case startsWith(path, "/api/v1/rules/") && method == fasthttp.MethodPut:
		h.updateRule(ctx)
	case startsWith(path, "/api/v1/rules/") && method == fasthttp.MethodDelete:
		h.deleteRule(ctx)

	case path == "/api/v1/users" && method == fasthttp.MethodGet:
		h.listUsers(ctx)
	case path == "/api/v1/users" && method == fasthttp.MethodPost:
		h.createUser(ctx)
	case startsWith(path, "/api/v1/users/") && method == fasthttp.MethodGet:
		h.getUser(ctx)
	case startsWith(path, "/api/v1/users/") && method == fasthttp.MethodPut:
		h.updateUser(ctx)
	case startsWith(path, "/api/v1/users/") && method == fasthttp.MethodDelete:
		h.deleteUser(ctx)

	case path == "/api/v1/stats" && method == fasthttp.MethodGet:
		h.stats(ctx)
	case path == "/api/v1/stats/rules" && method == fasthttp.MethodGet:
		h.statsRules(ctx)
	case path == "/api/v1/stats/users" && method == fasthttp.MethodGet:
		h.statsUsers(ctx)
	default:
		writeErr(ctx, 404, "not found")
	}
}

func startsWith(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func endsWith(s, p string) bool   { return len(s) >= len(p) && s[len(s)-len(p):] == p }

func pathID(path, prefix string) (uuid.UUID, error) {
	rest := path[len(prefix):]
	if i := indexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return uuid.Parse(rest)
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func pageParams(ctx *fasthttp.RequestCtx) models.PageParams {
	page, _ := strconv.Atoi(string(ctx.QueryArgs().Peek("page")))
	limit, _ := strconv.Atoi(string(ctx.QueryArgs().Peek("limit")))
	return models.PageParams{Page: page, Limit: limit}
}

func (h *Handler) issueDevToken(ctx *fasthttp.RequestCtx) {
	if h.BootstrapToken == "" {
		writeErr(ctx, fasthttp.StatusNotFound, "not found")
		return
	}
	got := string(ctx.Request.Header.Peek("X-Bootstrap-Token"))
	if got == "" || got != h.BootstrapToken {
		h.Log.Info("bootstrap token rejected", zap.String("ip", h.clientIP(ctx)))
		writeErr(ctx, fasthttp.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil || body.Email == "" {
		writeErr(ctx, 400, "email required")
		return
	}
	u, err := h.Repo.GetUserByEmail(context.Background(), body.Email)
	if err != nil {
		writeErr(ctx, 404, "user not found")
		return
	}
	if !u.Active {
		writeErr(ctx, 403, "user inactive")
		return
	}
	tok, err := h.Auth.IssueToken(u, 24*time.Hour)
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	h.audit(nil, "auth.bootstrap_token", u.ID.String(), h.clientIP(ctx), map[string]string{"email": u.Email})
	writeJSON(ctx, 200, map[string]string{"access_token": tok, "token_type": "Bearer"})
}

func (h *Handler) listRules(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermRulesRead) == nil {
		return
	}
	res, err := h.Repo.ListRules(context.Background(), pageParams(ctx))
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	writeJSON(ctx, 200, res)
}

func (h *Handler) createRule(ctx *fasthttp.RequestCtx) {
	tc := h.requirePerm(ctx, auth.PermRulesWrite)
	if tc == nil {
		return
	}
	var rule models.Rule
	if err := json.Unmarshal(ctx.PostBody(), &rule); err != nil {
		writeErr(ctx, 400, "invalid json")
		return
	}
	if err := filter.ValidateRule(&rule); err != nil {
		writeErr(ctx, 400, err.Error())
		return
	}
	uid := tc.UserID
	rule.CreatedBy = &uid
	if err := h.Repo.CreateRule(context.Background(), &rule); err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	_ = h.Cache.InvalidateRules(context.Background())
	h.reloadRules()
	h.audit(tc, "rule.create", rule.ID.String(), h.clientIP(ctx), rule)
	writeJSON(ctx, 201, rule)
}

func (h *Handler) getRule(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermRulesRead) == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/rules/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	r, err := h.Repo.GetRule(context.Background(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(ctx, 404, "not found")
		return
	}
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	writeJSON(ctx, 200, r)
}

func (h *Handler) updateRule(ctx *fasthttp.RequestCtx) {
	tc := h.requirePerm(ctx, auth.PermRulesWrite)
	if tc == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/rules/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	var rule models.Rule
	if err := json.Unmarshal(ctx.PostBody(), &rule); err != nil {
		writeErr(ctx, 400, "invalid json")
		return
	}
	rule.ID = id
	if err := filter.ValidateRule(&rule); err != nil {
		writeErr(ctx, 400, err.Error())
		return
	}
	if err := h.Repo.UpdateRule(context.Background(), &rule); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(ctx, 404, "not found")
			return
		}
		writeErr(ctx, 500, err.Error())
		return
	}
	_ = h.Cache.InvalidateRules(context.Background())
	h.reloadRules()
	h.audit(tc, "rule.update", id.String(), h.clientIP(ctx), rule)
	writeJSON(ctx, 200, rule)
}

func (h *Handler) deleteRule(ctx *fasthttp.RequestCtx) {
	tc := h.requirePerm(ctx, auth.PermRulesWrite)
	if tc == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/rules/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	if err := h.Repo.DeleteRule(context.Background(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(ctx, 404, "not found")
			return
		}
		writeErr(ctx, 500, err.Error())
		return
	}
	_ = h.Cache.InvalidateRules(context.Background())
	h.reloadRules()
	h.audit(tc, "rule.delete", id.String(), h.clientIP(ctx), nil)
	ctx.SetStatusCode(204)
}

func (h *Handler) testRule(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermRulesRead) == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/rules/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	rule, err := h.Repo.GetRule(context.Background(), id)
	if err != nil {
		writeErr(ctx, 404, "not found")
		return
	}
	var reqCtx models.RequestContext
	if err := json.Unmarshal(ctx.PostBody(), &reqCtx); err != nil {
		writeErr(ctx, 400, "invalid request context")
		return
	}
	ok, err := h.Filter.TestRule(rule, &reqCtx)
	if err != nil {
		writeErr(ctx, 400, err.Error())
		return
	}
	writeJSON(ctx, 200, map[string]any{"matched": ok, "action": rule.Action})
}

func (h *Handler) listUsers(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermUsersRead) == nil {
		return
	}
	res, err := h.Repo.ListUsers(context.Background(), pageParams(ctx))
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	writeJSON(ctx, 200, res)
}

func (h *Handler) createUser(ctx *fasthttp.RequestCtx) {
	tc := h.requirePerm(ctx, auth.PermUsersWrite)
	if tc == nil {
		return
	}
	var u models.User
	if err := json.Unmarshal(ctx.PostBody(), &u); err != nil {
		writeErr(ctx, 400, "invalid json")
		return
	}
	if u.Email == "" || u.Role == "" {
		writeErr(ctx, 400, "email and role required")
		return
	}
	if u.QuotaRPS == 0 {
		u.QuotaRPS = 1000
	}
	u.Active = true
	if err := h.Repo.CreateUser(context.Background(), &u); err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	h.audit(tc, "user.create", u.ID.String(), h.clientIP(ctx), u)
	writeJSON(ctx, 201, u)
}

func (h *Handler) getUser(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermUsersRead) == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/users/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	u, err := h.Repo.GetUser(context.Background(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(ctx, 404, "not found")
		return
	}
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	writeJSON(ctx, 200, u)
}

func (h *Handler) updateUser(ctx *fasthttp.RequestCtx) {
	tc := h.requirePerm(ctx, auth.PermUsersWrite)
	if tc == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/users/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	var u models.User
	if err := json.Unmarshal(ctx.PostBody(), &u); err != nil {
		writeErr(ctx, 400, "invalid json")
		return
	}
	u.ID = id
	if err := h.Repo.UpdateUser(context.Background(), &u); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(ctx, 404, "not found")
			return
		}
		writeErr(ctx, 500, err.Error())
		return
	}
	_ = h.Auth.SetUserActiveCache(context.Background(), id, u.Active, 10*time.Minute)
	_ = h.Auth.InvalidateUserCache(context.Background(), id)
	h.audit(tc, "user.update", id.String(), h.clientIP(ctx), u)
	writeJSON(ctx, 200, u)
}

func (h *Handler) deleteUser(ctx *fasthttp.RequestCtx) {
	tc := h.requirePerm(ctx, auth.PermUsersWrite)
	if tc == nil {
		return
	}
	id, err := pathID(string(ctx.Path()), "/api/v1/users/")
	if err != nil {
		writeErr(ctx, 400, "invalid id")
		return
	}
	if err := h.Repo.DeleteUser(context.Background(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(ctx, 404, "not found")
			return
		}
		writeErr(ctx, 500, err.Error())
		return
	}
	h.audit(tc, "user.delete", id.String(), h.clientIP(ctx), nil)
	ctx.SetStatusCode(204)
}

func (h *Handler) stats(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermStatsRead) == nil {
		return
	}
	writeJSON(ctx, 200, models.Stats{
		TotalRequests:   h.Metrics.TotalRequests(),
		BlockedRequests: h.Metrics.BlockedRequests(),
		ActiveConns:     h.Proxy.ActiveConns(),
		ActiveTunnels:   h.Proxy.ActiveTunnels(),
	})
}

func (h *Handler) statsRules(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermStatsRead) == nil {
		return
	}
	res, err := h.Repo.RuleStats(context.Background())
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	writeJSON(ctx, 200, res)
}

func (h *Handler) statsUsers(ctx *fasthttp.RequestCtx) {
	if h.requirePerm(ctx, auth.PermStatsRead) == nil {
		return
	}
	res, err := h.Repo.UserStats(context.Background())
	if err != nil {
		writeErr(ctx, 500, err.Error())
		return
	}
	writeJSON(ctx, 200, res)
}

func (h *Handler) reloadRules() {
	rules, err := h.Repo.ListEnabledRules(context.Background())
	if err != nil {
		h.Log.Warn("reload rules failed", zap.Error(err))
		return
	}
	h.Filter.SetRules(rules)
	_ = h.Cache.SetRules(context.Background(), rules)
}

// ReloadRulesFromDB экспортирована для запуска сервера.
func (h *Handler) ReloadRulesFromDB() { h.reloadRules() }
