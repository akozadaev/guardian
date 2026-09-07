// Package ratelimit ограничивает число одновременных соединений на IP.
package ratelimit

import (
	"sync"
	"sync/atomic"
)

// ConnTracker ограничивает количество одновременных соединений для каждого IP-адреса.
type ConnTracker struct {
	mu       sync.Mutex
	conns    map[string]*int64
	maxPerIP int
}

// NewConnTracker создаёт счётчик с заданным лимитом соединений на IP-адрес.
func NewConnTracker(maxPerIP int) *ConnTracker {
	if maxPerIP <= 0 {
		maxPerIP = 100
	}
	return &ConnTracker{conns: make(map[string]*int64), maxPerIP: maxPerIP}
}

// Acquire увеличивает счётчик для IP-адреса. Возвращает false при превышении лимита.
func (t *ConnTracker) Acquire(ip string) bool {
	t.mu.Lock()
	c, ok := t.conns[ip]
	if !ok {
		var n int64
		c = &n
		t.conns[ip] = c
	}
	t.mu.Unlock()
	if atomic.AddInt64(c, 1) > int64(t.maxPerIP) {
		atomic.AddInt64(c, -1)
		return false
	}
	return true
}

// Release уменьшает счётчик для IP-адреса.
func (t *ConnTracker) Release(ip string) {
	t.mu.Lock()
	c, ok := t.conns[ip]
	t.mu.Unlock()
	if !ok {
		return
	}
	if atomic.AddInt64(c, -1) <= 0 {
		t.mu.Lock()
		if atomic.LoadInt64(c) <= 0 {
			delete(t.conns, ip)
		}
		t.mu.Unlock()
	}
}
