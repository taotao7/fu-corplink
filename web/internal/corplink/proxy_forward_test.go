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

func setForwardStall(t *testing.T, d time.Duration) {
	t.Helper()
	prevStall, prevHeader, prevSwap := forwardStallTimeout, forwardHeaderTimeout, forwardSwapWait
	forwardStallTimeout = d
	forwardHeaderTimeout = d
	forwardSwapWait = 10 * time.Millisecond
	t.Cleanup(func() {
		forwardStallTimeout, forwardHeaderTimeout, forwardSwapWait = prevStall, prevHeader, prevSwap
	})
}

// queueDialer returns a Dialer whose i-th dial is served by the i-th handler
// (the last handler repeats). Each handler runs against the server side of a
// pipe, acting as a fake origin server.
func queueDialer(calls *atomic.Int32, handlers ...func(net.Conn)) Dialer {
	var idx atomic.Int32
	return dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		i := int(idx.Add(1)) - 1
		if i >= len(handlers) {
			i = len(handlers) - 1
		}
		c1, c2 := net.Pipe()
		go handlers[i](c2)
		return c1, nil
	})
}

// keepAliveOrigin serves any number of requests on one conn without closing it.
func keepAliveOrigin(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	}
}

// startForwardProxy starts a MixedProxy on a loopback port and returns a
// client conn to it plus a reader for responses.
func startForwardProxy(t *testing.T, d Dialer) (net.Conn, *bufio.Reader) {
	t.Helper()
	p := NewMixedProxy(d, nil)
	if err := p.ListenAndServe("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(p.Close)
	client, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	return client, bufio.NewReader(client)
}

func sendForwardGET(t *testing.T, conn net.Conn, path string) {
	t.Helper()
	req := fmt.Sprintf("GET http://origin.test%s HTTP/1.1\r\nHost: origin.test\r\n\r\n", path)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

func readForwardResp(t *testing.T, br *bufio.Reader) (int, string) {
	t.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// Each request on a kept-alive client conn must get its own upstream dial, so
// it rides the tunnel that is current at request time — not the tunnel that
// was current when the client conn was opened (which may be dead by now).
func TestForwardKeepAliveDialsPerRequest(t *testing.T) {
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, keepAliveOrigin))

	for i := 1; i <= 2; i++ {
		sendForwardGET(t, client, fmt.Sprintf("/req%d", i))
		status, body := readForwardResp(t, br)
		if status != 200 || body != "hello" {
			t.Fatalf("request %d: got %d %q", i, status, body)
		}
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("expected 2 upstream dials (one per request), got %d", got)
	}
}

// A second request must succeed even when the first upstream conn has become a
// silent blackhole (gateway revoked the old session): the request must not be
// piped into the dead conn.
func TestForwardSecondRequestSurvivesDeadUpstream(t *testing.T) {
	var dials atomic.Int32
	blackholeAfterFirst := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
		// swallow everything else, answer nothing, never close
		_, _ = io.Copy(io.Discard, conn)
	}
	client, br := startForwardProxy(t, queueDialer(&dials, blackholeAfterFirst, keepAliveOrigin))

	sendForwardGET(t, client, "/first")
	if status, _ := readForwardResp(t, br); status != 200 {
		t.Fatalf("first request: got %d", status)
	}
	sendForwardGET(t, client, "/second")
	status, body := readForwardResp(t, br)
	if status != 200 || body != "hello" {
		t.Fatalf("second request: got %d %q", status, body)
	}
}

// A GET whose body stalls mid-transfer (session revoked while a large asset is
// downloading) must be resumed on a fresh tunnel with a Range request, and the
// client must receive the complete body seamlessly.
func TestForwardResumesStalledBody(t *testing.T) {
	setForwardStall(t, 200*time.Millisecond)

	stallAfterHalf := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234"))
		_, _ = io.Copy(io.Discard, conn) // hang until proxy closes us
	}
	var gotRange atomic.Value
	resumeOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		gotRange.Store(req.Header.Get("Range"))
		_, _ = conn.Write([]byte("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 5-9/10\r\nContent-Length: 5\r\n\r\n56789"))
	}

	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, stallAfterHalf, resumeOrigin))

	sendForwardGET(t, client, "/big.js")
	status, body := readForwardResp(t, br)
	if status != 200 || body != "0123456789" {
		t.Fatalf("got %d %q, want 200 %q", status, body, "0123456789")
	}
	if r, _ := gotRange.Load().(string); r != "bytes=5-" {
		t.Fatalf("resume request Range = %q, want %q", r, "bytes=5-")
	}
}

// If the origin ignores Range and replies 200 with the full body, the proxy
// must discard the bytes it already relayed and forward only the rest.
func TestForwardResumeWhenRangeIgnored(t *testing.T) {
	setForwardStall(t, 200*time.Millisecond)

	stallAfterHalf := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234"))
		_, _ = io.Copy(io.Discard, conn)
	}
	fullOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"))
	}

	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, stallAfterHalf, fullOrigin))

	sendForwardGET(t, client, "/big.js")
	status, body := readForwardResp(t, br)
	if status != 200 || body != "0123456789" {
		t.Fatalf("got %d %q, want 200 %q", status, body, "0123456789")
	}
}

// Responses without Content-Length are delimited by connection close: the
// proxy must relay the body and signal Connection: close to the client.
func TestForwardUnknownLengthBody(t *testing.T) {
	closeDelimited := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nstream-data"))
		_ = conn.Close()
	}
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, closeDelimited))

	sendForwardGET(t, client, "/stream")
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "stream-data" {
		t.Fatalf("got %d %q", resp.StatusCode, string(body))
	}
	// Go's ReadResponse consumes "Connection: close" into resp.Close.
	if !resp.Close {
		t.Fatalf("expected close-delimited response (resp.Close=true)")
	}
}

// A zero-progress retry must wait for the refresher to swap in a fresh tunnel
// instead of immediately re-dialing the same dying one: attempts on a tunnel
// generation that already failed are wasted.
func TestForwardRetryWaitsForTunnelSwap(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)
	prevWait := forwardSwapWait
	forwardSwapWait = 2 * time.Second
	t.Cleanup(func() { forwardSwapWait = prevWait })

	var deadDials atomic.Int32
	deadDialer := dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		deadDials.Add(1)
		c1, c2 := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, c2) }() // swallow request, never answer
		return c1, nil
	})
	goodDialer := dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go keepAliveOrigin(c2)
		return c1, nil
	})

	p := NewMixedProxy(deadDialer, nil)
	if err := p.ListenAndServe("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(p.Close)

	// Swap in the good tunnel a moment after the first attempt has stalled.
	go func() {
		time.Sleep(400 * time.Millisecond)
		p.SetTunnel(goodDialer, nil)
	}()

	client, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(client)

	sendForwardGET(t, client, "/after-swap")
	status, body := readForwardResp(t, br)
	if status != 200 || body != "hello" {
		t.Fatalf("got %d %q, want 200 hello", status, body)
	}
	if d := deadDials.Load(); d != 1 {
		t.Fatalf("dead tunnel dialed %d times, want exactly 1 (retry must wait for swap)", d)
	}
}

// A chunked (unknown-length) body cut mid-chunk is a truncation, not a normal
// end-of-stream: the proxy must resume with Range and learn the total from the
// 206 Content-Range so the client receives the complete body.
func TestForwardResumesTruncatedChunkedBody(t *testing.T) {
	setForwardStall(t, 200*time.Millisecond)

	truncatedChunked := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		// one 5-byte chunk, then die mid-stream (no terminating 0-chunk)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n01234\r\n"))
		_ = conn.Close()
	}
	resumeOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Header.Get("Range") != "bytes=5-" {
			_, _ = conn.Write([]byte("HTTP/1.1 500 Bad Resume\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 5-9/10\r\nContent-Length: 5\r\n\r\n56789"))
	}

	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, truncatedChunked, resumeOrigin))

	sendForwardGET(t, client, "/big.js")
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "0123456789" {
		t.Fatalf("got %d %q, want 200 %q", resp.StatusCode, string(body), "0123456789")
	}
}

// The client's Accept-Encoding must pass through unchanged: forcing identity
// quadruples the wire size of compressed assets, which matters when gateway
// session windows are short. Resume safety over encoded bytes is guaranteed
// by overlap verification instead.
func TestForwardKeepsClientAcceptEncoding(t *testing.T) {
	var gotAE atomic.Value
	origin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		gotAE.Store(req.Header.Get("Accept-Encoding"))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	}
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, origin))

	req := "GET http://origin.test/a.js HTTP/1.1\r\nHost: origin.test\r\nAccept-Encoding: gzip, deflate\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	status, body := readForwardResp(t, br)
	if status != 200 || body != "hello" {
		t.Fatalf("got %d %q", status, body)
	}
	if ae, _ := gotAE.Load().(string); ae != "gzip, deflate" {
		t.Fatalf("origin saw Accept-Encoding %q, want %q", ae, "gzip, deflate")
	}
}

// Stall retries must be budgeted by consecutive zero-progress attempts, not
// total attempts: a transfer that stalls many times but advances each time
// (gateway revoking sessions every few seconds under a large download) must
// still complete.
func TestForwardResumeSurvivesManyProgressingStalls(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)

	const full = "0123456789abcdefghij" // 20 bytes
	step := 4                           // bytes served per conn before stalling
	var served atomic.Int32
	segmentOrigin := func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		off := 0
		if r := req.Header.Get("Range"); r != "" {
			fmt.Sscanf(r, "bytes=%d-", &off)
		}
		end := off + step
		if end > len(full) {
			end = len(full)
		}
		if off == 0 {
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(full))
		} else {
			fmt.Fprintf(conn, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %d-%d/%d\r\nContent-Length: %d\r\n\r\n",
				off, len(full)-1, len(full), len(full)-off)
		}
		_, _ = conn.Write([]byte(full[off:end]))
		served.Add(1)
		if end < len(full) {
			_, _ = io.Copy(io.Discard, conn) // stall: hold conn open, send nothing
		}
	}
	var dials atomic.Int32
	client, br := startForwardProxy(t, queueDialer(&dials, segmentOrigin))

	sendForwardGET(t, client, "/big.js")
	status, body := readForwardResp(t, br)
	if status != 200 || body != full {
		t.Fatalf("got %d %q, want 200 %q", status, body, full)
	}
	if s := served.Load(); s < 5 {
		t.Fatalf("expected >=5 segment conns (progress-based retries), got %d", s)
	}
}

// A dial failure on a retryable GET must not 502 immediately: the next
// attempt may land on a freshly-rotated tunnel and succeed.
func TestForwardRetriesFailedDial(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)

	var calls atomic.Int32
	flaky := dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return nil, fmt.Errorf("dial: %w", context.DeadlineExceeded)
		}
		c1, c2 := net.Pipe()
		go keepAliveOrigin(c2)
		return c1, nil
	})
	client, br := startForwardProxy(t, flaky)

	sendForwardGET(t, client, "/doc")
	status, body := readForwardResp(t, br)
	if status != 200 || body != "hello" {
		t.Fatalf("got %d %q, want 200 hello", status, body)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected >=2 dial attempts, got %d", got)
	}
}

// A dial failure on a non-retryable request must still 502 immediately.
func TestForwardDialFailure502OnPost(t *testing.T) {
	setForwardStall(t, 150*time.Millisecond)
	dead := dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("connect tcp 10.0.0.1:80: connection was refused")
	})
	client, br := startForwardProxy(t, dead)

	req := "POST http://origin.test/submit HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 2\r\n\r\nhi"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	status, _ := readForwardResp(t, br)
	if status != 502 {
		t.Fatalf("got %d, want 502", status)
	}
}
