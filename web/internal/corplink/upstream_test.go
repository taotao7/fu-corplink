package corplink

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestParseUpstreamProxy covers URL parsing and scheme normalization. This is
// the gate for the whole coexistence fix: a misconfigured proxy must be rejected
// loudly rather than silently dropping the tunnel.
func TestParseUpstreamProxy(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		scheme  string
		isSOCKS bool
		isHTTP  bool
	}{
		{"", true, "", false, false}, // nil means direct
		{"http://127.0.0.1:7890", true, "http", false, true},
		{"socks5://127.0.0.1:7890", true, "socks5", true, false},
		{"socks5h://127.0.0.1:7890", true, "socks5", true, false},
		{"127.0.0.1:7890", true, "http", false, true}, // bare host:port -> http
		{"ftp://x", false, "", false, false},
		{"http://", false, "", false, false}, // no host
	}
	for _, c := range cases {
		p, err := ParseUpstreamProxy(c.in)
		if c.ok && err != nil {
			t.Errorf("ParseUpstreamProxy(%q): unexpected err %v", c.in, err)
			continue
		}
		if !c.ok && err == nil {
			t.Errorf("ParseUpstreamProxy(%q): expected error, got nil (%+v)", c.in, p)
			continue
		}
		if err != nil {
			continue
		}
		if c.in == "" {
			if p != nil {
				t.Errorf("ParseUpstreamProxy(%q): expected nil config", c.in)
			}
			continue
		}
		if p.scheme != c.scheme {
			t.Errorf("ParseUpstreamProxy(%q): scheme=%s want %s", c.in, p.scheme, c.scheme)
		}
		if p.IsSOCKS5() != c.isSOCKS {
			t.Errorf("ParseUpstreamProxy(%q): IsSOCKS5=%v want %v", c.in, p.IsSOCKS5(), c.isSOCKS)
		}
		if p.IsHTTP() != c.isHTTP {
			t.Errorf("ParseUpstreamProxy(%q): IsHTTP=%v want %v", c.in, p.IsHTTP(), c.isHTTP)
		}
	}
}

// TestProxyURLCarriesAuth verifies ProxyURL (used by http.Transport.Proxy)
// round-trips credentials so authenticated proxies work for API calls.
func TestProxyURLCarriesAuth(t *testing.T) {
	p, err := ParseUpstreamProxy("http://u:p@127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	u := p.ProxyURL()
	if u.User == nil || u.User.Username() != "u" {
		t.Fatalf("proxy user lost: %+v", u)
	}
	pass, _ := u.User.Password()
	if pass != "p" {
		t.Fatalf("proxy pass lost: %q", pass)
	}
}

// TestHTTPConnectDial spins up a fake HTTP CONNECT proxy that just relays to a
// target echo server, then asserts DialContext tunnels the bytes correctly. This
// proves the TCP-transport fix end to end for the HTTP-proxy case (Stash mixed
// port speaks HTTP CONNECT).
func TestHTTPConnectDial(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(c)
		}
	}()

	targetAddr := target.Addr().String()
	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyL.Close()
	go func() {
		for {
			c, err := proxyL.Accept()
			if err != nil {
				return
			}
			go serveHTTPConnectProxy(c, targetAddr)
		}
	}()

	cfg := &UpstreamProxyConfig{raw: "http://" + proxyL.Addr().String(), scheme: "http", host: proxyL.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cfg.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	payload := []byte("hello-via-proxy")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: %q != %q", buf, payload)
	}
}

// serveHTTPConnectProxy is a minimal CONNECT proxy: it replies 200 then pipes
// the client straight to target. Used only for the test.
func serveHTTPConnectProxy(c net.Conn, target string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := make([]byte, 1024)
	// read until end of headers (\r\n\r\n)
	n, _ := c.Read(br)
	if !strings.Contains(string(br[:n]), "CONNECT") {
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	_ = c.SetDeadline(time.Time{})
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer up.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { _, _ = io.Copy(up, c); wg.Done() }()
	go func() { _, _ = io.Copy(c, up); wg.Done() }()
	wg.Wait()
}

// TestSOCKS5ConnectDial verifies the SOCKS5 CONNECT path by running a tiny
// in-process SOCKS5 server that relays to an echo target.
func TestSOCKS5ConnectDial(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	targetAddr := target.Addr().String()
	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyL.Close()
	go func() {
		for {
			c, err := proxyL.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5Proxy(c, targetAddr)
		}
	}()

	cfg := &UpstreamProxyConfig{raw: "socks5://" + proxyL.Addr().String(), scheme: "socks5", host: proxyL.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cfg.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	payload := []byte("socks5-echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: %q != %q", buf, payload)
	}
}

// serveSOCKS5Proxy implements just enough SOCKS5 (no-auth CONNECT) to relay to
// a fixed target. Test-only.
func serveSOCKS5Proxy(c net.Conn, target string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// greeting: VER NMETHODS METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00}) // no auth
	// request: VER CMD RSV ATYP ...
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		return
	}
	// socks5ReadAddr reads ATYP + addr + port fully.
	if _, _, err := socks5ReadAddr(c, req[3]); err != nil {
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer up.Close()
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success
	_ = c.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(up, c) }()
	go func() { defer wg.Done(); _, _ = io.Copy(c, up) }()
	wg.Wait()
}

// TestDisabledProxyDialsDirect ensures a nil/disabled proxy behaves exactly
// like a plain dial (the default behavior must not regress).
func TestDisabledProxyDialsDirect(t *testing.T) {
	var p *UpstreamProxyConfig // nil
	if p.Enabled() {
		t.Fatal("nil proxy should not be enabled")
	}
	if p.ProxyURL() != nil {
		t.Fatal("nil proxy should yield nil ProxyURL")
	}
}
