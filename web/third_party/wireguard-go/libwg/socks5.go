package main

// SOCKS5 proxy backed by github.com/things-go/go-socks5. Outbound connections
// are dialed through the WireGuard userspace netstack (tnet), and hostnames are
// resolved inside the tunnel, so traffic never touches any system interface,
// route table or resolver. Authentication is optional: with credentials it
// requires username/password (RFC 1929); without, it accepts the no-auth method.

import (
	"context"
	"net"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// dnsCacheTTL is how long a successful resolution is reused. On a lossy
// WireGuard-over-TCP link a DNS round-trip is expensive and often lost, and
// browsers open many parallel connections to the same host. Caching the result
// turns N lookups per page into 1.
const dnsCacheTTL = 5 * time.Minute

// dnsLookupRetries is how many times to retry a failed/timed-out lookup before
// giving up. A single UDP/TCP DNS attempt is frequently dropped on a lossy
// link; retrying a few times makes resolution reliable at the cost of latency.
const dnsLookupRetries = 4

type dnsCacheEntry struct {
	ip      net.IP
	expires time.Time
}

// netstackResolver resolves hostnames inside the tunnel via the netstack DNS,
// so SOCKS5 requests for internal names work without touching the host resolver.
// Results are cached and lookups retried to survive lossy links.
type netstackResolver struct {
	tnet  *netstack.Net
	mu    sync.Mutex
	cache map[string]dnsCacheEntry
}

func newNetstackResolver(tnet *netstack.Net) *netstackResolver {
	return &netstackResolver{tnet: tnet, cache: make(map[string]dnsCacheEntry)}
}

func (r *netstackResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Literal IPs need no DNS lookup. This also covers the 0.0.0.0 placeholder
	// that clients send as the source address in a UDP ASSOCIATE request.
	if ip := net.ParseIP(name); ip != nil {
		return ctx, ip, nil
	}
	// Some clients (e.g. PySocks) send "0" or "" as the UDP ASSOCIATE source
	// placeholder; the Go stdlib resolver maps "0" to 0.0.0.0, so mirror that
	// rather than failing the whole associate setup with "no such host".
	if name == "" || name == "0" {
		return ctx, net.IPv4zero, nil
	}

	// Serve from cache when fresh.
	r.mu.Lock()
	if e, ok := r.cache[name]; ok && time.Now().Before(e.expires) {
		ip := e.ip
		r.mu.Unlock()
		return ctx, ip, nil
	}
	r.mu.Unlock()

	// Retry the lookup; lossy links drop individual DNS round-trips.
	var lastErr error
	for attempt := 0; attempt < dnsLookupRetries; attempt++ {
		addrs, err := r.tnet.LookupHost(name)
		if err != nil {
			lastErr = err
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				r.mu.Lock()
				r.cache[name] = dnsCacheEntry{ip: ip, expires: time.Now().Add(dnsCacheTTL)}
				r.mu.Unlock()
				return ctx, ip, nil
			}
		}
		lastErr = &net.DNSError{Err: "no addresses found", Name: name}
	}
	return ctx, nil, lastErr
}

// socksLogger adapts device.Logger to the go-socks5 Logger interface.
type socksLogger struct {
	logger *device.Logger
}

func (l socksLogger) Errorf(format string, args ...interface{}) {
	l.logger.Errorf("socks5: "+format, args...)
}

// startSocks5 binds a SOCKS5 listener on the host and serves it in the
// background. When username is non-empty, username/password authentication is
// required (clients offering only no-auth are rejected).
func startSocks5(listen, username, password string, tnet *netstack.Net, logger *device.Logger) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}

	opts := []socks5.Option{
		socks5.WithResolver(newNetstackResolver(tnet)),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, addr)
		}),
		socks5.WithLogger(socksLogger{logger: logger}),
	}
	if username != "" {
		// go-socks5 enables UserPassAuthenticator only (no no-auth fallback)
		// once credentials are set, so unauthenticated clients are rejected.
		opts = append(opts, socks5.WithCredential(socks5.StaticCredentials{
			username: password,
		}))
		logger.Verbosef("socks5: username/password authentication enabled")
	}

	server := socks5.NewServer(opts...)
	go func() {
		if err := server.Serve(ln); err != nil {
			logger.Errorf("socks5: serve stopped: %v", err)
		}
	}()
	return nil
}
