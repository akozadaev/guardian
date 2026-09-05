package netutil

import (
	"net"
	"net/netip"
	"strings"
)

// IsPrivateOrLocal сообщает, является ли IP-адрес кольцевым, локальным для канала, частным или неопределённым.
func IsPrivateOrLocal(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 169 && ip4[1] == 254: // локальный для канала адрес / метаданные облака
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // NAT операторского класса (CGNAT)
			return true
		}
		return false
	}
	// Локальные IPv6-адреса ULA fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

// HostIsBlockedForProxy разрешает имя хоста (без порта) и возвращает true, если хотя бы один адрес частный или локальный,
// либо если allowPrivate равен false и при ошибке разрешения доступ запрещается по умолчанию.
func HostIsBlockedForProxy(host string, allowPrivate bool) bool {
	if allowPrivate {
		return false
	}
	h := host
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(h); ip != nil {
		return IsPrivateOrLocal(ip)
	}
	// Блокируем очевидные имена localhost без обращения к DNS.
	lower := strings.ToLower(h)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		return true
	}
	addrs, err := net.LookupIP(h)
	if err != nil {
		// Запрещаем доступ при ошибке: целевой адрес невозможно проверить.
		return true
	}
	for _, a := range addrs {
		if IsPrivateOrLocal(a) {
			return true
		}
	}
	return false
}

// ClientIP возвращает настоящий IP-адрес клиента.
// X-Forwarded-For / X-Real-IP считаются доверенными, только когда remoteAddr входит в trustedProxies.
func ClientIP(remoteAddr string, xff, xRealIP string, trustedProxies []netip.Prefix) string {
	host := remoteHost(remoteAddr)
	remoteIP, err := netip.ParseAddr(host)
	if err != nil {
		// Пробуем без зоны.
		if i := strings.IndexByte(host, '%'); i >= 0 {
			remoteIP, err = netip.ParseAddr(host[:i])
		}
	}
	if err != nil {
		return host
	}

	if !isTrusted(remoteIP, trustedProxies) {
		return remoteIP.String()
	}

	if xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			p := strings.TrimSpace(parts[i])
			if p == "" {
				continue
			}
			if addr, err := netip.ParseAddr(p); err == nil {
				if !isTrusted(addr, trustedProxies) {
					return addr.String()
				}
				continue
			}
			return p
		}
	}
	if xRealIP != "" {
		p := strings.TrimSpace(xRealIP)
		if addr, err := netip.ParseAddr(p); err == nil {
			return addr.String()
		}
		return p
	}
	return remoteIP.String()
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs преобразует список строк CIDR в сетевые префиксы.
func ParseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			// Разрешаем одиночный IP-адрес.
			addr, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, err
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			p = netip.PrefixFrom(addr, bits)
		}
		out = append(out, p)
	}
	return out, nil
}
