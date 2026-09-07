package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akozadaev/guardian/internal/config"
	"github.com/akozadaev/guardian/internal/netutil"
	"github.com/valyala/fasthttp"
)

// ErrPrivateTarget возвращается при подключении к заблокированному частному или локальному адресу.
var ErrPrivateTarget = fmt.Errorf("destination blocked: private or local address")

var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 32*1024))
	},
}

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func PutBuffer(b *bytes.Buffer) {
	b.Reset()
	bufferPool.Put(b)
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Core выполняет перенаправление HTTP-запросов и туннелирование HTTPS CONNECT.
type Core struct {
	client       *fasthttp.Client
	dialer       *fasthttp.TCPDialer
	activeConns  atomic.Int64
	activeTunnel atomic.Int64
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64
	cfg          config.ProxyConfig
	allowPrivate bool
}

func NewCore(cfg config.ProxyConfig, allowPrivate bool) *Core {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 32 * 1024
	}
	if cfg.DialConcurrency == 0 {
		cfg.DialConcurrency = 4096
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = 1000
	}
	dialer := &fasthttp.TCPDialer{
		Concurrency:      cfg.DialConcurrency,
		DNSCacheDuration: cfg.DNSCacheTTL,
	}
	client := &fasthttp.Client{
		Name:                "guardian-proxy",
		MaxConnsPerHost:     cfg.MaxConnsPerHost,
		ReadTimeout:         cfg.ReadTimeout,
		WriteTimeout:        cfg.WriteTimeout,
		MaxIdleConnDuration: cfg.MaxIdleConnDuration,
		DialDualStack:       true,
		Dial:                dialer.Dial,
	}
	return &Core{client: client, dialer: dialer, cfg: cfg, allowPrivate: allowPrivate}
}

func (c *Core) ActiveConns() int64   { return c.activeConns.Load() }
func (c *Core) ActiveTunnels() int64 { return c.activeTunnel.Load() }
func (c *Core) BytesIn() int64       { return c.bytesIn.Load() }
func (c *Core) BytesOut() int64      { return c.bytesOut.Load() }

// ForwardHTTP проксирует обычный HTTP-запрос.
func (c *Core) ForwardHTTP(ctx *fasthttp.RequestCtx, clientIP string) error {
	c.activeConns.Add(1)
	defer c.activeConns.Add(-1)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	ctx.Request.CopyTo(req)

	uri := req.URI()
	host := string(uri.Host())
	if host == "" {
		host = string(req.Host())
	}
	if host == "" {
		return fmt.Errorf("missing upstream host")
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	if netutil.HostIsBlockedForProxy(hostname, c.allowPrivate) {
		return ErrPrivateTarget
	}

	if len(uri.Host()) > 0 {
		req.SetRequestURIBytes(uri.RequestURI())
		req.SetHostBytes(uri.Host())
	}

	stripHopByHop(req)
	// Никогда не передаём учётные данные клиента вышестоящему серверу.
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")

	appendXFF(req, clientIP)

	if err := c.client.Do(req, resp); err != nil {
		return err
	}

	c.bytesOut.Add(int64(len(ctx.Request.Body())))
	c.bytesIn.Add(int64(len(resp.Body())))

	resp.CopyTo(&ctx.Response)
	stripResponseHopByHop(&ctx.Response)
	return nil
}

// HandleCONNECT устанавливает TCP-туннель для HTTPS.
func (c *Core) HandleCONNECT(ctx *fasthttp.RequestCtx) error {
	c.activeConns.Add(1)
	defer c.activeConns.Add(-1)

	host := string(ctx.Host())
	if host == "" {
		host = string(ctx.Request.URI().Host())
	}
	if host == "" {
		return fmt.Errorf("missing host")
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	} else {
		host = net.JoinHostPort(host, "443")
	}
	if netutil.HostIsBlockedForProxy(hostname, c.allowPrivate) {
		return ErrPrivateTarget
	}

	timeout := c.cfg.DialTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	dest, err := c.dialer.DialTimeout(host, timeout)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.HijackSetNoResponse(true)
	ctx.Hijack(func(clientConn net.Conn) {
		defer func() { _ = dest.Close() }()
		c.activeTunnel.Add(1)
		defer c.activeTunnel.Add(-1)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, _ := copyBuf(dest, clientConn)
			c.bytesOut.Add(n)
			closeWrite(dest)
		}()
		go func() {
			defer wg.Done()
			n, _ := copyBuf(clientConn, dest)
			c.bytesIn.Add(n)
			closeWrite(clientConn)
		}()
		wg.Wait()
	})
	return nil
}

func stripHopByHop(req *fasthttp.Request) {
	// Удаляем заголовки, перечисленные в Connection.
	connHdr := string(req.Header.Peek("Connection"))
	if connHdr != "" {
		for _, h := range strings.Split(connHdr, ",") {
			req.Header.Del(strings.TrimSpace(h))
		}
	}
	for _, h := range hopByHopHeaders {
		req.Header.Del(h)
	}
}

func stripResponseHopByHop(resp *fasthttp.Response) {
	connHdr := string(resp.Header.Peek("Connection"))
	if connHdr != "" {
		for _, h := range strings.Split(connHdr, ",") {
			resp.Header.Del(strings.TrimSpace(h))
		}
	}
	for _, h := range hopByHopHeaders {
		resp.Header.Del(h)
	}
}

func copyBuf(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	return io.CopyBuffer(dst, src, buf)
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func appendXFF(req *fasthttp.Request, clientIP string) {
	if clientIP == "" {
		return
	}
	existing := string(req.Header.Peek("X-Forwarded-For"))
	if existing == "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", existing+", "+clientIP)
	}
	req.Header.Set("X-Real-IP", clientIP)
}

func ApplyModifySpec(req *fasthttp.Request, add, set map[string]string, remove []string) {
	for _, h := range remove {
		req.Header.Del(h)
	}
	for k, v := range add {
		req.Header.Add(k, v)
	}
	for k, v := range set {
		req.Header.Set(k, v)
	}
}
