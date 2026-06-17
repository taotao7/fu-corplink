package corplink

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// handleHTTP serves an HTTP proxy request: either a CONNECT tunnel (for HTTPS)
// or a plain forward proxy request (absolute-URI GET/POST/etc).
func (p *MixedProxy) handleHTTP(client net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if p.auth.required() && !p.checkHTTPAuth(req) {
		_, _ = client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"corplink\"\r\n" +
			"Content-Length: 0\r\n\r\n"))
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(client, req)
		return
	}
	p.handleForward(client, br, req)
}

func (p *MixedProxy) checkHTTPAuth(req *http.Request) bool {
	const prefix = "Basic "
	h := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, prefix))
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	return ok && user == p.auth.Username && pass == p.auth.Password
}

// handleConnect establishes a tunnel for an HTTP CONNECT request (HTTPS).
func (p *MixedProxy) handleConnect(client net.Conn, req *http.Request) {
	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	upstream, err := p.dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	relay(client, upstream, bufio.NewReader(client))
}

// handleForward proxies a plain (non-CONNECT) HTTP request through the tunnel.
func (p *MixedProxy) handleForward(client net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	target := net.JoinHostPort(hostnameOnly(host), port)

	upstream, err := p.dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer upstream.Close()

	// strip hop-by-hop / proxy headers and forward as an origin-form request
	req.RequestURI = ""
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = host
	}

	if err := req.Write(upstream); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	go func() { _, _ = io.Copy(upstream, br) }()
	_, _ = io.Copy(client, upstream)
}

func hostnameOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
