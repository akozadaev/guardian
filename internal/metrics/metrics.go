package metrics

import (
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector содержит метрики Prometheus для прокси-сервера.
type Collector struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	activeConns     prometheus.Gauge
	activeTunnels   prometheus.Gauge
	bytesIn         prometheus.Counter
	bytesOut        prometheus.Counter
	blockedTotal    prometheus.Counter
	ruleHits        *prometheus.CounterVec

	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	lastBytesIn     atomic.Int64
	lastBytesOut    atomic.Int64
}

func New() *Collector {
	return &Collector{
		requestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_requests_total",
			Help: "Total number of proxied requests",
		}, []string{"method", "status"}),
		requestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardian_request_duration_seconds",
			Help:    "Request latency in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"method"}),
		activeConns: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "guardian_active_connections",
			Help: "Current number of active connections",
		}),
		activeTunnels: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "guardian_active_tunnels",
			Help: "Current number of CONNECT tunnels",
		}),
		bytesIn: promauto.NewCounter(prometheus.CounterOpts{
			Name: "guardian_bytes_in_total",
			Help: "Total bytes received from upstream",
		}),
		bytesOut: promauto.NewCounter(prometheus.CounterOpts{
			Name: "guardian_bytes_out_total",
			Help: "Total bytes sent to upstream",
		}),
		blockedTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "guardian_blocked_requests_total",
			Help: "Total blocked requests",
		}),
		ruleHits: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_rule_hits_total",
			Help: "Hits per filter rule",
		}, []string{"rule_id", "rule_name"}),
	}
}

func (c *Collector) ObserveRequest(method string, status int, seconds float64) {
	c.requestsTotal.WithLabelValues(method, strconv.Itoa(status)).Inc()
	c.requestDuration.WithLabelValues(method).Observe(seconds)
	c.totalRequests.Add(1)
}

func (c *Collector) ObserveBlocked(ruleID, ruleName string) {
	c.blockedTotal.Inc()
	c.blockedRequests.Add(1)
	if ruleID != "" {
		c.ruleHits.WithLabelValues(ruleID, ruleName).Inc()
	}
}

func (c *Collector) SetActiveConns(n int64)   { c.activeConns.Set(float64(n)) }
func (c *Collector) SetActiveTunnels(n int64) { c.activeTunnels.Set(float64(n)) }

// SyncBytes записывает в счётчики Prometheus разницу с момента последней синхронизации.
func (c *Collector) SyncBytes(in, out int64) {
	prevIn := c.lastBytesIn.Swap(in)
	prevOut := c.lastBytesOut.Swap(out)
	if d := in - prevIn; d > 0 {
		c.bytesIn.Add(float64(d))
	}
	if d := out - prevOut; d > 0 {
		c.bytesOut.Add(float64(d))
	}
}

func (c *Collector) AddBytesIn(n int64) {
	if n > 0 {
		c.bytesIn.Add(float64(n))
	}
}
func (c *Collector) AddBytesOut(n int64) {
	if n > 0 {
		c.bytesOut.Add(float64(n))
	}
}

func (c *Collector) TotalRequests() int64   { return c.totalRequests.Load() }
func (c *Collector) BlockedRequests() int64 { return c.blockedRequests.Load() }

// Handler возвращает HTTP-обработчик Prometheus.
func Handler() http.Handler {
	return promhttp.Handler()
}
