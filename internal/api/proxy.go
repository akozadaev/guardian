package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/akozadaev/guardian/internal/auth"
	"github.com/akozadaev/guardian/internal/filter"
	"github.com/akozadaev/guardian/internal/models"
	"github.com/akozadaev/guardian/internal/proxy"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// ProxyHandler - обработчик fasthttp для публичного порта прокси-сервера.
func (h *Handler) ProxyHandler(ctx *fasthttp.RequestCtx) {
	start := time.Now()
	method := string(ctx.Method())
	ip := h.clientIP(ctx)
	reqID := uuid.New()

	if h.ConnTracker != nil {
		if !h.ConnTracker.Acquire(ip) {
			writeErr(ctx, fasthttp.StatusTooManyRequests, "too many connections from IP")
			h.observe(method, fasthttp.StatusTooManyRequests, start)
			return
		}
		defer h.ConnTracker.Release(ip)
	}

	if h.MaxBody > 0 && len(ctx.PostBody()) > h.MaxBody {
		writeErr(ctx, fasthttp.StatusRequestEntityTooLarge, "request body too large")
		h.observe(method, fasthttp.StatusRequestEntityTooLarge, start)
		return
	}

	if h.RateLimitEnabled {
		if !h.Auth.AllowRate("ip:"+ip, h.PerIPLimit) {
			writeErr(ctx, fasthttp.StatusTooManyRequests, "rate limit exceeded")
			h.observe(method, fasthttp.StatusTooManyRequests, start)
			return
		}
	}

	var tc *models.TokenClaims
	if authz := string(ctx.Request.Header.Peek("Authorization")); authz != "" {
		if claims, err := h.Auth.ValidateToken(context.Background(), authz); err == nil {
			tc = claims
			if h.RateLimitEnabled {
				if !h.Auth.AllowRate("user:"+claims.UserID.String(), claims.QuotaRPS) {
					writeErr(ctx, fasthttp.StatusTooManyRequests, "user quota exceeded")
					h.observe(method, fasthttp.StatusTooManyRequests, start)
					return
				}
			}
		} else if h.RequireProxyAuth {
			h.Log.Info("auth failed", zap.String("ip", ip), zap.Error(err))
			writeErr(ctx, fasthttp.StatusUnauthorized, "unauthorized")
			h.observe(method, fasthttp.StatusUnauthorized, start)
			return
		}
	} else if h.RequireProxyAuth {
		writeErr(ctx, fasthttp.StatusUnauthorized, "unauthorized")
		h.observe(method, fasthttp.StatusUnauthorized, start)
		return
	}

	if tc != nil && !auth.HasPermission(tc.Role, auth.PermProxyAccess) {
		writeErr(ctx, fasthttp.StatusForbidden, "forbidden")
		h.observe(method, fasthttp.StatusForbidden, start)
		return
	}

	if method == fasthttp.MethodConnect {
		rctx := h.buildRequestContext(ctx, ip, tc)
		res := h.Filter.Evaluate(rctx)
		if res.Matched && res.Action == models.ActionBlock {
			h.block(ctx, res, start, method, reqID, tc)
			return
		}
		if err := h.Proxy.HandleCONNECT(ctx); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusBadGateway)
			h.observe(method, fasthttp.StatusBadGateway, start)
			h.logRequest(reqID, method, string(ctx.Host()), fasthttp.StatusBadGateway, start, tc, &res)
			return
		}
		// Длительность туннеля неизвестна до завершения hijack; записываем только задержку принятия соединения.
		h.observe(method, fasthttp.StatusOK, start)
		h.logRequest(reqID, method, string(ctx.Host()), fasthttp.StatusOK, start, tc, &res)
		h.Metrics.SetActiveTunnels(h.Proxy.ActiveTunnels())
		return
	}

	rctx := h.buildRequestContext(ctx, ip, tc)
	res := h.Filter.Evaluate(rctx)

	if res.Matched && res.Action == models.ActionBlock {
		h.block(ctx, res, start, method, reqID, tc)
		return
	}

	if res.Matched && res.Action == models.ActionModify && res.Modify != nil {
		proxy.ApplyModifySpec(&ctx.Request, res.Modify.AddHeaders, res.Modify.SetHeaders, res.Modify.RemoveHeaders)
	}

	cacheKey := ""
	if h.ResponseCacheOn && method == fasthttp.MethodGet && tc == nil &&
		len(ctx.Request.Header.Peek("Cookie")) == 0 &&
		len(ctx.Request.Header.Peek("Authorization")) == 0 {
		cacheKey = responseCacheKey(string(ctx.Host()), string(ctx.RequestURI()))
		if cached, ok := h.Cache.GetResponse(context.Background(), cacheKey); ok {
			var packed cachedResponse
			if json.Unmarshal(cached, &packed) == nil {
				ctx.SetStatusCode(packed.Status)
				ctx.SetBody(packed.Body)
				for k, v := range packed.Headers {
					ctx.Response.Header.Set(k, v)
				}
				h.observe(method, packed.Status, start)
				return
			}
		}
	}

	if err := h.Proxy.ForwardHTTP(ctx, ip); err != nil {
		h.Log.Warn("forward failed", zap.Error(err), zap.String("url", string(ctx.URI().FullURI())))
		status := fasthttp.StatusBadGateway
		if errors.Is(err, proxy.ErrPrivateTarget) {
			status = fasthttp.StatusForbidden
		}
		ctx.Error(err.Error(), status)
		h.observe(method, status, start)
		h.logRequest(reqID, method, string(ctx.URI().FullURI()), status, start, tc, &res)
		return
	}

	status := ctx.Response.StatusCode()
	if cacheKey != "" && status == 200 && isCacheableResponse(&ctx.Response) {
		hdrs := map[string]string{}
		ctx.Response.Header.VisitAll(func(k, v []byte) {
			hdrs[string(k)] = string(v)
		})
		packed, _ := json.Marshal(cachedResponse{
			Status:  status,
			Body:    append([]byte(nil), ctx.Response.Body()...),
			Headers: hdrs,
		})
		_ = h.Cache.SetResponse(context.Background(), cacheKey, packed)
	}

	if res.Matched && res.Action == models.ActionModify && res.Modify != nil && res.Modify.BodyReplace != "" {
		ctx.SetBodyString(res.Modify.BodyReplace)
	}

	h.Metrics.SetActiveConns(h.Proxy.ActiveConns())
	h.Metrics.SetActiveTunnels(h.Proxy.ActiveTunnels())
	h.observe(method, status, start)
	h.logRequest(reqID, method, string(ctx.URI().FullURI()), status, start, tc, &res)
}

type cachedResponse struct {
	Status  int               `json:"status"`
	Body    []byte            `json:"body"`
	Headers map[string]string `json:"headers"`
}

func isCacheableResponse(resp *fasthttp.Response) bool {
	// Ответ устанавливает cookie - общий кэш запрещён.
	if len(resp.Header.Peek("Set-Cookie")) > 0 {
		return false
	}

	// Пока Vary не входит в ключ кэша, такие ответы кэшировать нельзя.
	if len(resp.Header.Peek("Vary")) > 0 {
		return false
	}

	cacheControl := string(resp.Header.Peek("Cache-Control"))

	hasPublic := false

	for _, part := range strings.Split(cacheControl, ",") {
		directive := strings.TrimSpace(part)

		// Например: max-age=60 → max-age
		if name, _, found := strings.Cut(directive, "="); found {
			directive = strings.TrimSpace(name)
		}

		switch {
		case strings.EqualFold(directive, "public"):
			hasPublic = true

		case strings.EqualFold(directive, "private"),
			strings.EqualFold(directive, "no-store"),
			strings.EqualFold(directive, "no-cache"):
			return false
		}
	}

	return hasPublic
}

func (h *Handler) block(ctx *fasthttp.RequestCtx, res filter.Result, start time.Time, method string, reqID uuid.UUID, tc *models.TokenClaims) {
	status := 403
	body := "Access denied"
	if res.Response != nil {
		if res.Response.Status != 0 {
			status = res.Response.Status
		}
		if res.Response.Body != "" {
			body = res.Response.Body
		}
		for k, v := range res.Response.Headers {
			ctx.Response.Header.Set(k, v)
		}
	}
	ctx.SetStatusCode(status)
	ctx.SetBodyString(body)
	ruleID, ruleName := "", ""
	if res.Rule != nil {
		ruleID = res.Rule.ID.String()
		ruleName = res.Rule.Name
	}
	h.Metrics.ObserveBlocked(ruleID, ruleName)
	h.observe(method, status, start)
	h.logRequest(reqID, method, string(ctx.URI().FullURI()), status, start, tc, &res)
}

func (h *Handler) buildRequestContext(ctx *fasthttp.RequestCtx, ip string, tc *models.TokenClaims) *models.RequestContext {
	headers := make(map[string]string, 16)
	ctx.Request.Header.VisitAll(func(k, v []byte) {
		headers[string(k)] = string(v)
	})
	r := &models.RequestContext{
		Method:      string(ctx.Method()),
		URL:         string(ctx.URI().FullURI()),
		Path:        string(ctx.Path()),
		Query:       string(ctx.URI().QueryString()),
		Host:        string(ctx.Host()),
		IP:          ip,
		Headers:     headers,
		Body:        ctx.PostBody(),
		ContentType: string(ctx.Request.Header.ContentType()),
		BodySize:    len(ctx.PostBody()),
	}
	if tc != nil {
		r.UserID = tc.UserID.String()
		r.Role = string(tc.Role)
	}
	return r
}

func (h *Handler) observe(method string, status int, start time.Time) {
	h.Metrics.ObserveRequest(method, status, time.Since(start).Seconds())
}

func (h *Handler) logRequest(reqID uuid.UUID, method, url string, status int, start time.Time, tc *models.TokenClaims, res *filter.Result) {
	ms := int(time.Since(start).Milliseconds())
	var uid *uuid.UUID
	if tc != nil {
		id := tc.UserID
		uid = &id
	}
	var ruleID *uuid.UUID
	if res != nil && res.Rule != nil {
		id := res.Rule.ID
		ruleID = &id
	}
	log := &models.RequestLog{
		ID:             uuid.New(),
		RequestID:      reqID,
		Method:         method,
		URL:            url,
		StatusCode:     status,
		ResponseTimeMs: ms,
		UserID:         uid,
		RuleID:         ruleID,
		CreatedAt:      time.Now().UTC(),
	}
	go func() {
		_ = h.Queue.PublishRequestLog(context.Background(), log)
		if h.PersistRequestLogs {
			_ = h.Repo.InsertRequestLog(context.Background(), log)
		}
	}()
}

func responseCacheKey(host, uri string) string {
	sum := sha256.Sum256([]byte(host + "\n" + uri))
	return hex.EncodeToString(sum[:16])
}
