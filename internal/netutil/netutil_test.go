package netutil

import (
	"net"
	"testing"
)

func TestIsPrivateOrLocal(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":            true,
		"10.0.0.1":             true,
		"192.168.1.1":          true,
		"169.254.169.254":      true,
		"8.8.8.8":              false,
		"::1":                  true,
		"2001:4860:4860::8888": false,
	}
	for ip, want := range cases {
		got := IsPrivateOrLocal(net.ParseIP(ip))
		if got != want {
			t.Fatalf("%s: got %v want %v", ip, got, want)
		}
	}
}

func TestClientIPTrustsXFFOnlyFromProxy(t *testing.T) {
	trusted, err := ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	// Прямое подключение клиента - игнорируем поддельный XFF.
	got := ClientIP("1.2.3.4:1234", "9.9.9.9", "", trusted)
	if got != "1.2.3.4" {
		t.Fatalf("got %s", got)
	}
	// Подключение через доверенный прокси - получаем адрес клиента из XFF.
	got = ClientIP("10.0.0.5:1234", "9.9.9.9, 10.0.0.5", "", trusted)
	if got != "9.9.9.9" {
		t.Fatalf("got %s", got)
	}
}

func TestHostIsBlockedForProxy(t *testing.T) {
	if !HostIsBlockedForProxy("127.0.0.1", false) {
		t.Fatal("expected block localhost IP")
	}
	if !HostIsBlockedForProxy("localhost", false) {
		t.Fatal("expected block localhost name")
	}
	if HostIsBlockedForProxy("127.0.0.1", true) {
		t.Fatal("allowPrivate should permit")
	}
}
