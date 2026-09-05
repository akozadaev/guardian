package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/akozadaev/guardian/internal/api"
	"github.com/akozadaev/guardian/internal/auth"
	"github.com/akozadaev/guardian/internal/cache"
	"github.com/akozadaev/guardian/internal/config"
	"github.com/akozadaev/guardian/internal/filter"
	"github.com/akozadaev/guardian/internal/metrics"
	"github.com/akozadaev/guardian/internal/netutil"
	"github.com/akozadaev/guardian/internal/proxy"
	"github.com/akozadaev/guardian/internal/queue"
	"github.com/akozadaev/guardian/internal/ratelimit"
	"github.com/akozadaev/guardian/internal/repository"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// App связывает все компоненты и запускает серверы.
type App struct {
	cfg     *config.Config
	log     *zap.Logger
	repo    *repository.Store
	cache   *cache.Store
	auth    *auth.Service
	filter  *filter.Engine
	proxy   *proxy.Core
	metrics *metrics.Collector
	queue   queue.Publisher
	handler *api.Handler
	ready   atomic.Bool
}

func New(cfg *config.Config) (*App, error) {
	log, err := newLogger(cfg.Log)
	if err != nil {
		return nil, err
	}

	if auth.WeakSecret(cfg.Auth.JWTSecret) {
		return nil, fmt.Errorf("auth.jwt_secret is missing or insecure; set GUARDIAN_AUTH_JWT_SECRET to a strong value (≥16 chars)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	repo, err := repository.NewStore(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	rdb := cache.NewRedisClient(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB, cfg.Redis.PoolSize)
	store := cache.NewStore(rdb, cfg.Redis.Enabled, cfg.Cache.RulesTTL, cfg.Cache.AuthTTL, cfg.Cache.ResponseTTL)
	if cfg.Redis.Enabled {
		if err := store.Ping(ctx); err != nil {
			log.Warn("redis unavailable, falling back to memory cache", zap.Error(err))
			_ = rdb.Close()
			store = cache.NewStore(nil, false, cfg.Cache.RulesTTL, cfg.Cache.AuthTTL, cfg.Cache.ResponseTTL)
		}
	} else {
		_ = rdb.Close()
		store = cache.NewStore(nil, false, cfg.Cache.RulesTTL, cfg.Cache.AuthTTL, cfg.Cache.ResponseTTL)
	}

	authSvc := auth.NewService(
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTIssuer,
		store,
		cfg.Auth.TokenCacheTTL,
		cfg.RateLimit.DefaultRPS,
		cfg.RateLimit.Burst,
	)

	engine := filter.NewEngine()
	core := proxy.NewCore(cfg.Proxy, cfg.Proxy.AllowPrivateTargets)
	mc := metrics.New()

	brokers := strings.Split(cfg.Queue.Brokers, ",")
	pub := queue.NewPublisher(cfg.Queue.Enabled, cfg.Queue.Backend, brokers, cfg.Queue.Topic, log)

	trusted, err := netutil.ParseCIDRs(cfg.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("trusted_proxies: %w", err)
	}

	app := &App{
		cfg: cfg, log: log, repo: repo, cache: store, auth: authSvc,
		filter: engine, proxy: core, metrics: mc, queue: pub,
	}

	if cfg.Auth.BootstrapToken != "" {
		log.Warn("auth.bootstrap_token is set: POST /api/v1/auth/token is enabled (dev only)")
	}

	h := &api.Handler{
		Repo:               repo,
		Auth:               authSvc,
		Filter:             engine,
		Cache:              store,
		Proxy:              core,
		Metrics:            mc,
		Queue:              pub,
		Log:                log,
		RequireProxyAuth:   cfg.Auth.RequireAuthForProxy,
		RateLimitEnabled:   cfg.RateLimit.Enabled,
		PerIPLimit:         cfg.RateLimit.PerIPLimit,
		MaxBody:            cfg.Server.MaxRequestBody,
		TrustedProxies:     trusted,
		BootstrapToken:     cfg.Auth.BootstrapToken,
		ConnTracker:        ratelimit.NewConnTracker(cfg.RateLimit.MaxConnsPerIP),
		ResponseCacheOn:    cfg.Cache.Enabled && cfg.Cache.ResponseEnabled,
		PersistRequestLogs: cfg.Log.PersistRequests,
		Ready:              func() bool { return app.ready.Load() },
	}
	app.handler = h
	return app, nil
}

func (a *App) Run() error {
	a.handler.ReloadRulesFromDB()
	a.ready.Store(true)

	go func() {
		t := time.NewTicker(a.cfg.Cache.RulesTTL)
		defer t.Stop()
		for range t.C {
			a.handler.ReloadRulesFromDB()
		}
	}()

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			a.metrics.SetActiveConns(a.proxy.ActiveConns())
			a.metrics.SetActiveTunnels(a.proxy.ActiveTunnels())
			a.metrics.SyncBytes(a.proxy.BytesIn(), a.proxy.BytesOut())
		}
	}()

	proxySrv := &fasthttp.Server{
		Handler:               a.handler.ProxyHandler,
		Name:                  "guardian-proxy",
		ReadTimeout:           a.cfg.Server.ReadTimeout,
		WriteTimeout:          a.cfg.Server.WriteTimeout,
		IdleTimeout:           a.cfg.Server.IdleTimeout,
		MaxRequestBodySize:    a.cfg.Server.MaxRequestBody,
		Concurrency:           a.cfg.Server.MaxConns,
		NoDefaultServerHeader: true,
		NoDefaultDate:         true,
	}

	adminSrv := &fasthttp.Server{
		Handler:               a.handler.AdminRouter,
		Name:                  "guardian-admin",
		ReadTimeout:           a.cfg.Server.ReadTimeout,
		WriteTimeout:          a.cfg.Server.WriteTimeout,
		NoDefaultServerHeader: true,
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Handler())
	metricsMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	metricsHTTP := &http.Server{Addr: a.cfg.Server.MetricsAddr, Handler: metricsMux}

	errCh := make(chan error, 3)

	go func() {
		a.log.Info("proxy listening", zap.String("addr", a.cfg.Server.ProxyAddr))
		if err := proxySrv.ListenAndServe(a.cfg.Server.ProxyAddr); err != nil {
			errCh <- fmt.Errorf("proxy: %w", err)
		}
	}()
	go func() {
		a.log.Info("admin listening", zap.String("addr", a.cfg.Server.AdminAddr))
		if err := adminSrv.ListenAndServe(a.cfg.Server.AdminAddr); err != nil {
			errCh <- fmt.Errorf("admin: %w", err)
		}
	}()
	go func() {
		a.log.Info("metrics listening", zap.String("addr", a.cfg.Server.MetricsAddr))
		if err := metricsHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("metrics: %w", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		a.log.Info("shutdown signal", zap.String("signal", sig.String()))
	}

	a.ready.Store(false)
	shutdownTimeout := a.cfg.Server.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	_ = proxySrv.ShutdownWithContext(ctx)
	_ = adminSrv.ShutdownWithContext(ctx)
	_ = metricsHTTP.Shutdown(ctx)
	_ = a.queue.Close()
	a.repo.Close()
	a.log.Info("shutdown complete")
	return nil
}

func newLogger(cfg config.LogConfig) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	_ = level.UnmarshalText([]byte(cfg.Level))
	var zc zap.Config
	if cfg.Format == "console" {
		zc = zap.NewDevelopmentConfig()
	} else {
		zc = zap.NewProductionConfig()
	}
	zc.Level = zap.NewAtomicLevelAt(level)
	return zc.Build()
}
