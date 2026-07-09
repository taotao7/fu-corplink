package corplink

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Content-hashed asset URLs (Vite/webpack "name-HASH.ext") are immutable by
// construction: the same path can never carry different bytes.
func TestIsImmutableAssetPath(t *testing.T) {
	yes := []string{
		"/assets/index-sICwX53r.js",
		"/assets/index-B4gaBhbm.css",
		"/static/js/main.8f4b2c1a.chunk.js",
		"/assets/Geometry-BgaF_0id.js",
		"/assets/Filter-KaMOlR-S.js", // Vite base64url hash containing '-'
		"/fonts/inter-v13-latin-Q0plLmNv.woff2",
	}
	no := []string{
		"/anomalies",
		"/api/anomalies?page=1",
		"/index.js",              // no hash segment
		"/app-v2.js",             // "v2" too short to be a hash
		"/assets/",               // no file
		"/data.json",             // no hash
		"/src/my-component.js",   // word, not a hash (single char class)
		"/lib/eventemitter3.js",  // version-ish name, no hash segment
	}
	for _, p := range yes {
		if !isImmutableAssetPath(p) {
			t.Errorf("expected immutable: %s", p)
		}
	}
	for _, p := range no {
		if isImmutableAssetPath(p) {
			t.Errorf("expected NOT immutable: %s", p)
		}
	}
}

// A fully-relayed immutable asset must be served from cache on the next
// request — no upstream dial — so tunnel churn can't break repeat loads.
func TestForwardCachesImmutableAsset(t *testing.T) {
	origin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		for {
			if _, err := http.ReadRequest(br); err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\nContent-Length: 5\r\n\r\nhello"))
		}
	}
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, origin))

	for i := 1; i <= 3; i++ {
		sendForwardGET(t, client, "/assets/app-deadBEEF.js")
		status, body := readForwardResp(t, br)
		if status != 200 || body != "hello" {
			t.Fatalf("request %d: got %d %q", i, status, body)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("expected 1 upstream dial (rest from cache), got %d", got)
	}
}

// Non-immutable paths must never be cached: each request hits the origin.
func TestForwardDoesNotCacheDynamicPath(t *testing.T) {
	var serve atomic.Int32
	origin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		for {
			if _, err := http.ReadRequest(br); err != nil {
				return
			}
			n := serve.Add(1)
			body := fmt.Sprintf("resp%d", n)
			_, _ = conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)))
		}
	}
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, origin))

	sendForwardGET(t, client, "/api/data")
	if _, body := readForwardResp(t, br); body != "resp1" {
		t.Fatalf("got %q", body)
	}
	sendForwardGET(t, client, "/api/data")
	if _, body := readForwardResp(t, br); body != "resp2" {
		t.Fatalf("got %q, want fresh origin response", body)
	}
}

// A truncated (stalled, incomplete) transfer must not poison the cache.
func TestForwardDoesNotCacheTruncatedAsset(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)

	stallForever := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234"))
		_, _ = io.Copy(io.Discard, conn)
	}
	goodOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		for {
			if _, err := http.ReadRequest(br); err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"))
		}
	}
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, stallForever, goodOrigin))

	sendForwardGET(t, client, "/assets/app-deadBEEF.js")
	if status, body := readForwardResp(t, br); status != 200 || body != "0123456789" {
		t.Fatalf("got %d %q", status, body)
	}
	firstDials := dials.Load()

	// second request: full body was assembled via resume, which must not have
	// been cached as-is unless it represents the complete object
	sendForwardGET(t, client, "/assets/app-deadBEEF.js")
	if status, body := readForwardResp(t, br); status != 200 || body != "0123456789" {
		t.Fatalf("repeat: got %d %q", status, body)
	}
	_ = firstDials
}

// cachePut/cacheGet basic behavior incl. size cap eviction.
func TestAssetCacheEviction(t *testing.T) {
	c := newAssetCache(100) // 100-byte budget
	c.put("a", cachedResponse{header: "H", body: make([]byte, 60)})
	c.put("b", cachedResponse{header: "H", body: make([]byte, 30)})
	if _, ok := c.get("a"); !ok {
		t.Fatalf("a should be cached")
	}
	// inserting c (60B) must evict the least-recently-used entry (b)
	c.put("c", cachedResponse{header: "H", body: make([]byte, 30)})
	if _, ok := c.get("a"); !ok {
		t.Fatalf("a should survive (recently used)")
	}
	if _, ok := c.get("b"); ok {
		t.Fatalf("b should be evicted")
	}
	if _, ok := c.get("c"); !ok {
		t.Fatalf("c should be cached")
	}
	// an object larger than the whole budget is never cached
	c.put("huge", cachedResponse{header: "H", body: make([]byte, 200)})
	if _, ok := c.get("huge"); ok {
		t.Fatalf("huge should not be cached")
	}
}

// dial helper reused from proxy_forward_test.go (queueDialer, startForwardProxy,
// sendForwardGET, readForwardResp, setForwardStall).
var _ = context.Background

// Partial progress on an immutable asset must survive across client requests:
// when request 1 dies with only a prefix relayed, request 2 serves that prefix
// from cache instantly and only fetches the remainder (via Range), so progress
// on a huge asset accumulates monotonically across browser retries instead of
// restarting from zero each time.
func TestForwardPartialProgressSharedAcrossRequests(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)

	stallAt5 := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234"))
		_, _ = io.Copy(io.Discard, conn) // stall forever
	}

	var sawRange atomic.Value
	fullOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if r := req.Header.Get("Range"); r != "" {
			sawRange.Store(r)
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"))
	}

	var dials atomic.Int32
	// request 1: every attempt stalls at 5 bytes -> gives up with a partial
	// request 2: origin healthy -> must complete using the cached prefix
	p := NewMixedProxy(queueDialer(&dials,
		stallAt5, stallAt5, stallAt5, stallAt5, stallAt5, stallAt5, stallAt5, stallAt5, stallAt5,
		fullOrigin), nil)
	if err := p.ListenAndServe("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(p.Close)

	// request 1 (its conn dies with a truncated body; ignore the error)
	c1, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = c1.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(c1, "GET http://origin.test/assets/big-deadBEEF.js HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	_, _ = io.ReadAll(c1) // drain whatever arrives until conn closes
	c1.Close()

	// request 2 must deliver the complete, correct body
	c2, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(c2, "GET http://origin.test/assets/big-deadBEEF.js HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	br2 := bufio.NewReader(c2)
	resp, err := http.ReadResponse(br2, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "0123456789" {
		t.Fatalf("request 2: got %d %q, want 200 0123456789", resp.StatusCode, string(body))
	}
	if r, _ := sawRange.Load().(string); r != "bytes=5-" {
		t.Fatalf("request 2 resume Range = %q, want bytes=5- (prefix from request 1)", r)
	}
}

// A stalled immutable asset must be completed by a background fetcher (with
// no client attached, immune to the client giving up) and land in the full
// cache, so a later request is served instantly from cache. The client here
// disconnects almost immediately — only a background completion can warm the
// cache.
func TestBackgroundCompleterWarmsCache(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)

	// First dial (the client's) stalls after 5 bytes. Subsequent dials (the
	// background completer's) succeed with the full body.
	stallAt5 := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234"))
		_, _ = io.Copy(io.Discard, conn)
	}
	fullOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		for {
			if _, err := http.ReadRequest(br); err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"))
		}
	}
	var dials atomic.Int32
	p := NewMixedProxy(queueDialer(&dials, stallAt5, fullOrigin), nil)
	if err := p.ListenAndServe("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(p.Close)

	// client request 1: reads the 5-byte prefix then disconnects hard —
	// in-band resume can no longer deliver to it, so only a background
	// completion can finish the object.
	c1, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprintf(c1, "GET http://origin.test/assets/big-deadBEEF.js HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	buf := make([]byte, 4096)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c1.Read(buf) // header+prefix arrives, then the body stalls
	c1.Close()          // give up like a browser canceling the request

	// the background completer must fill the full cache within a short while
	key := "origin.test/assets/big-deadBEEF.js"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cr, ok := p.assets.get(key); ok && string(cr.body) == "0123456789" {
			return // success: cache warmed by background fetch
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background completer never warmed the cache for %s", key)
}
