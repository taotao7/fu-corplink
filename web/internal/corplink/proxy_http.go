package corplink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Forward-proxy timing knobs. Vars (not consts) so tests can shrink them.
var (
	// forwardStallTimeout bounds how long a response body may make zero
	// progress before the proxy abandons the upstream conn and resumes on a
	// fresh tunnel — the signature of the gateway revoking the session
	// mid-transfer. Short: on a live tunnel LAN assets always progress.
	forwardStallTimeout = 4 * time.Second
	// forwardHeaderTimeout bounds request-write + response-header wait; longer
	// than the body stall window because it includes origin processing time.
	forwardHeaderTimeout = 15 * time.Second
	// forwardHeaderTimeoutRetryable is the tighter first-byte bound for
	// idempotent (resumable) requests: LAN origins answer in well under a
	// second, so waiting the full budget on a dead-window tunnel only inflates
	// tail latency — fail fast, kick the refresher, retry on the next tunnel.
	// Non-idempotent requests keep the generous budget since they get no retry.
	forwardHeaderTimeoutRetryable = 8 * time.Second
	// forwardIdleTimeout bounds how long a kept-alive client conn may sit idle
	// between requests before the proxy closes it.
	forwardIdleTimeout = 2 * time.Minute
	// forwardSwapWait bounds how long a stalled request waits for the refresher
	// to swap in a fresh tunnel before retrying anyway. Must exceed one rotation
	// period (18s) plus tunnel build time so a retry lands on a new generation.
	forwardSwapWait = 30 * time.Second
)

// forwardResumeAttempts caps consecutive zero-progress retries per request.
// Attempts that advance the body reset the budget. Generous because the origin
// may ignore Range (resume = re-download + skip), so an attempt only counts as
// progress once it outruns all previous ones — under aggressive gateway session
// revocation several fresh-tunnel windows may be needed.
const forwardResumeAttempts = 8

// forwardMaxAttempts is an absolute backstop on per-request upstream dials.
const forwardMaxAttempts = 64

// hopByHopRespHeaders are stripped from proxied responses; the proxy manages
// its own connection semantics toward the client.
var hopByHopRespHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Connection",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// handleHTTP serves an HTTP proxy request: either a CONNECT tunnel (for HTTPS)
// or a plain forward proxy request (absolute-URI GET/POST/etc). Forward-proxy
// client conns are kept alive and served request-by-request.
func (p *MixedProxy) handleHTTP(client net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	for {
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
		if !p.handleForward(client, br, req) {
			return
		}
		// next request on the kept-alive client conn
		_ = client.SetDeadline(time.Now().Add(forwardIdleTimeout))
		req, err = http.ReadRequest(br)
		if err != nil {
			return
		}
	}
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
	host, port := splitHostPortDefault(req.Host, "443")
	if host == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	// Plain-HTTP CONNECT tunnels (upstream proxies like Stash/Clash CONNECT
	// even for port-80 traffic) carry parseable HTTP: interpose the forward
	// machinery so inner requests get the same resume + immutable-asset cache
	// treatment as direct forward-proxy requests, instead of a raw pipe that
	// dies with the tunnel generation.
	if port == "80" {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		_ = client.SetDeadline(time.Now().Add(forwardIdleTimeout))
		br := bufio.NewReader(client)
		for {
			inner, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			if inner.Host == "" {
				inner.Host = req.Host
			}
			if !p.handleForward(client, br, inner) {
				return
			}
			_ = client.SetDeadline(time.Now().Add(forwardIdleTimeout))
		}
	}
	upstream, err := p.dialContext(context.Background(), "tcp", host, port)
	if err != nil {
		log.Printf("http connect dial %s:%s failed: %v", host, port, err)
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	tuneProxyConn(upstream)
	defer upstream.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	relay(client, upstream, bufio.NewReader(client))
}

// forwardOnce outcomes.
const (
	fwdDone  = iota // response fully relayed; client conn may serve another request
	fwdRetry        // transient tunnel failure; retry/resume on a fresh tunnel
	fwdAbort        // unrecoverable; close the client conn
)

// forwardState tracks per-request relay progress across resume attempts.
type forwardState struct {
	headerSent bool  // response header already written to the client
	relayed    int64 // body bytes already written to the client
	total      int64 // expected body length; -1 when unknown
	closeAfter bool  // response is close-delimited; client conn can't be reused

	// pending accumulates body bytes received before the header is sent to the
	// client (unknown-length buffering mode): the response is reframed with an
	// explicit Content-Length once complete, so nothing is written until then.
	pending []byte

	// cacheKey, when non-empty, marks this response as an immutable asset to
	// capture: header/buf accumulate the exact bytes sent to the client and
	// are committed to the cache only when the body completes.
	cacheKey string
	header   string
	buf      []byte
}

// handleForward proxies one plain (non-CONNECT) HTTP request through the
// tunnel. It dials upstream per request — never reusing a possibly-dead
// tunnel conn — and, when a known-length response stalls mid-body (the
// gateway revoking the session under a large download), resumes it on a
// fresh tunnel with a Range request so the client sees one seamless
// response. Returns true if the client conn can serve another request.
func (p *MixedProxy) handleForward(client net.Conn, br *bufio.Reader, req *http.Request) bool {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return false
	}
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}

	// Buffer the request body so the request can be replayed on a fresh
	// tunnel. Plain-HTTP forward bodies are small; HTTPS uses CONNECT.
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
		req.Body.Close()
		if err != nil {
			return false
		}
		body = b
	}

	// strip hop-by-hop / proxy headers and forward as an absolute-form request
	req.RequestURI = ""
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = host
	}

	// Protocol upgrades (websockets) need a raw bidirectional pipe.
	if req.Header.Get("Upgrade") != "" {
		p.forwardRaw(client, br, req, body, host, port)
		return false
	}

	// Only idempotent requests without a caller-supplied Range are safe to
	// replay/resume. The client's Accept-Encoding passes through untouched:
	// a compressed body is ~4x smaller on the wire, which matters when the
	// gateway revokes sessions under load — resume-skip works on encoded
	// bytes because static-asset responses are byte-stable across requests.
	canRetry := (req.Method == http.MethodGet || req.Method == http.MethodHead) &&
		req.Header.Get("Range") == ""

	// Content-hashed assets are immutable: serve repeat loads from cache so
	// they don't depend on tunnel health, and capture them on first fetch.
	cacheKey := ""
	if req.Method == http.MethodGet && canRetry && isImmutableAssetPath(req.URL.Path) {
		cacheKey = host + req.URL.Path
		if cached, ok := p.assets.get(cacheKey); ok {
			_ = client.SetWriteDeadline(time.Now().Add(forwardHeaderTimeout))
			if _, err := client.Write([]byte(cached.header)); err != nil {
				return false
			}
			if _, err := client.Write(cached.body); err != nil {
				return false
			}
			_ = client.SetWriteDeadline(time.Time{})
			return !cached.close
		}
	}

	_ = client.SetDeadline(time.Time{})
	st := &forwardState{total: -1, cacheKey: cacheKey}

	// Resume from a previously-interrupted transfer of the same asset: replay
	// the stored prefix to this client and continue fetching from that offset,
	// so progress on a large asset accumulates across browser retries.
	if cacheKey != "" {
		if pa, ok := p.assets.getPartial(cacheKey); ok {
			_ = client.SetWriteDeadline(time.Now().Add(forwardHeaderTimeout))
			if _, err := client.Write([]byte(pa.header)); err != nil {
				return false
			}
			if _, err := client.Write(pa.body); err != nil {
				return false
			}
			_ = client.SetWriteDeadline(time.Time{})
			st.headerSent = true
			st.header = pa.header
			st.buf = append([]byte(nil), pa.body...)
			st.relayed = int64(len(pa.body))
			st.total = pa.total
			st.closeAfter = pa.closeAfter
		}
	}

	zeroProgress := 0
	for attempt := 0; attempt < forwardMaxAttempts; attempt++ {
		gen, _ := p.tunnelGen()
		before := st.relayed + int64(len(st.pending))
		switch p.forwardOnce(client, req, body, st, host, port, canRetry) {
		case fwdDone:
			return !st.closeAfter
		case fwdAbort:
			p.savePartial(st)
			return false
		case fwdRetry:
			if !canRetry {
				if !st.headerSent {
					_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
				}
				return false
			}
			// Budget by consecutive zero-progress attempts: a transfer that
			// advances each time is healthy resumption, not a hard failure.
			// Progress may accrue either as relayed bytes (streaming mode) or
			// buffered pending bytes (unknown-length reframing mode).
			if st.relayed+int64(len(st.pending)) > before {
				zeroProgress = 0
			} else {
				zeroProgress++
				if zeroProgress >= forwardResumeAttempts {
					if !st.headerSent {
						_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
					}
					p.savePartial(st)
					return false
				}
			}
			log.Printf("http forward %s%s stalled (relayed %d/%d), waiting for fresh tunnel",
				host, req.URL.Path, st.relayed, st.total)
			// The tunnel generation this attempt used already proved dead —
			// kick the refresher to rotate now (instead of waiting out the
			// periodic timer) and block until the fresh tunnel is in place.
			// Gated on evidence the destination itself works (bytes already
			// relayed, or a recent successful dial to the host), so a
			// perpetually-unreachable destination (e.g. OS connectivity
			// probes leaking into the proxy) can't thrash the rotation cadence.
			if st.relayed+int64(len(st.pending)) > 0 || p.hostWasLive(hostnameOnly(host)) {
				p.kickRefresh()
			}
			p.waitTunnelSwap(gen, forwardSwapWait)
		}
	}
	if !st.headerSent {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
	}
	p.savePartial(st)
	return false
}

// savePartial stores the relayed prefix of an interrupted cacheable transfer
// so the next request for the same asset continues where this one stopped.
func (p *MixedProxy) savePartial(st *forwardState) {
	if st.cacheKey == "" || st.header == "" || len(st.buf) == 0 {
		return
	}
	p.assets.putPartial(st.cacheKey, partialAsset{
		header:     st.header,
		body:       st.buf,
		total:      st.total,
		closeAfter: st.closeAfter,
	})
}

// forwardOnce performs one attempt: dial a fresh upstream through the current
// tunnel, send the request (with a Range header when resuming a partially
// relayed body), and relay the response with stall detection. canRetry selects
// the tighter first-byte timeout for requests that will be retried on failure.
func (p *MixedProxy) forwardOnce(client net.Conn, req *http.Request, body []byte, st *forwardState, host, port string, canRetry bool) int {
	upstream, err := p.dialContext(context.Background(), "tcp", hostnameOnly(host), port)
	if err != nil {
		log.Printf("http forward dial %s:%s failed: %v", hostnameOnly(host), port, err)
		// A dead-tunnel dial (timeout after dialContext's own retry budget) is
		// still worth another forward-level attempt after the next tunnel swap;
		// a definitive refusal is a real answer.
		if !st.headerSent && isRetryableDialError(err) {
			return fwdRetry
		}
		if !st.headerSent {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		}
		return fwdAbort
	}
	tuneProxyConn(upstream)
	defer upstream.Close()

	outReq := req.Clone(context.Background())
	if len(body) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(body))
		outReq.ContentLength = int64(len(body))
	} else {
		outReq.Body = http.NoBody
	}
	resuming := st.headerSent && st.relayed > 0
	buffering := !st.headerSent && len(st.pending) > 0
	if resuming {
		outReq.Header.Set("Range", fmt.Sprintf("bytes=%d-", st.relayed))
	} else if buffering {
		outReq.Header.Set("Range", fmt.Sprintf("bytes=%d-", len(st.pending)))
	}

	headerBudget := forwardHeaderTimeout
	if canRetry {
		headerBudget = forwardHeaderTimeoutRetryable
	}
	_ = upstream.SetWriteDeadline(time.Now().Add(headerBudget))
	if err := outReq.Write(upstream); err != nil {
		return fwdRetry
	}
	_ = upstream.SetWriteDeadline(time.Time{})

	_ = upstream.SetReadDeadline(time.Now().Add(headerBudget))
	resp, err := http.ReadResponse(bufio.NewReader(upstream), outReq)
	if err != nil {
		return fwdRetry
	}
	defer resp.Body.Close()

	// Bytes of the resumed body to discard before relaying (origin ignored
	// our Range and replied 200 with the full representation).
	var skip int64
	if resuming || buffering {
		offset := st.relayed
		if buffering {
			offset = int64(len(st.pending))
		}
		switch resp.StatusCode {
		case http.StatusPartialContent:
			cr := resp.Header.Get("Content-Range")
			want := fmt.Sprintf("bytes %d-", offset)
			if !strings.HasPrefix(cr, want) {
				return fwdAbort // offset mismatch; can't splice safely
			}
			// Learn the complete length ("bytes 5-9/10") when the original
			// response didn't carry one (chunked/close-delimited).
			if st.total < 0 {
				if slash := strings.LastIndexByte(cr, '/'); slash >= 0 {
					if n, err := strconv.ParseInt(cr[slash+1:], 10, 64); err == nil {
						st.total = n
					}
				}
			}
		case http.StatusOK:
			skip = offset
		default:
			return fwdAbort
		}
	}

	if !st.headerSent {
		if !buffering {
			st.total = resp.ContentLength
			if req.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent ||
				resp.StatusCode == http.StatusNotModified || resp.StatusCode < 200 {
				st.total = 0
			}
		}
		// Unknown-length bodies (chunked or close-delimited origins) would force
		// close-delimited framing toward the client — but CONNECT-tunneling
		// upstreams (Stash/Clash) hold the client conn keep-alive and don't
		// propagate our FIN, so the client never sees EOF and a browser never
		// finishes parsing the document. Buffer bounded unknown-length bodies and
		// reframe with an explicit Content-Length instead.
		if st.total < 0 || buffering {
			return p.forwardBuffered(client, resp, upstream, st, skip)
		}
		st.closeAfter = false
		hdr, err := writeForwardHeader(client, resp, st.closeAfter)
		if err != nil {
			return fwdAbort
		}
		st.headerSent = true
		// Capture only plain 200s of bounded size for the immutable cache.
		if st.cacheKey != "" {
			if resp.StatusCode == http.StatusOK && st.total <= assetCacheMaxObject {
				st.header = hdr
			} else {
				st.cacheKey = ""
			}
		}
	}

	return p.relayForwardBody(client, resp.Body, upstream, st, skip)
}

// forwardBufferedMax bounds how much of an unknown-length body is buffered for
// Content-Length reframing; larger bodies fall back to close-delimited
// streaming (rare: SPA HTML and API responses are far smaller).
const forwardBufferedMax = 8 << 20 // 8 MiB

// forwardBuffered accumulates an unknown-length response body into st.pending
// (with stall detection, resumable across attempts) and, once complete,
// replays it to the client with explicit Content-Length framing, so the
// client's EOF never depends on connection teardown.
func (p *MixedProxy) forwardBuffered(client net.Conn, resp *http.Response, upstream net.Conn, st *forwardState, skip int64) int {
	buf := proxyCopyBufferPool.Get().([]byte)
	defer proxyCopyBufferPool.Put(buf)
	for {
		if st.total >= 0 && int64(len(st.pending)) >= st.total {
			return p.finishBuffered(client, resp, st)
		}
		_ = upstream.SetReadDeadline(time.Now().Add(forwardStallTimeout))
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if skip > 0 {
				drop := skip
				if drop > int64(n) {
					drop = int64(n)
				}
				chunk = chunk[drop:]
				skip -= drop
			}
			if len(chunk) > 0 {
				if int64(len(st.pending))+int64(len(chunk)) > forwardBufferedMax {
					return p.streamOverflowBuffered(client, resp, upstream, st, chunk)
				}
				st.pending = append(st.pending, chunk...)
			}
		}
		if err != nil {
			// A chunked stream cut mid-chunk surfaces as ErrUnexpectedEOF:
			// that's a truncation even when the total length is unknown.
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fwdRetry
			}
			if errors.Is(err, io.EOF) {
				if st.total < 0 || int64(len(st.pending)) >= st.total {
					return p.finishBuffered(client, resp, st)
				}
				return fwdRetry // truncated mid-body — resume on a fresh tunnel
			}
			if isTimeoutErr(err) {
				return fwdRetry // stalled — resume on a fresh tunnel
			}
			return fwdAbort
		}
	}
}

// finishBuffered writes the fully-buffered body to the client as a single
// Content-Length-framed keep-alive response and commits the immutable cache.
func (p *MixedProxy) finishBuffered(client net.Conn, resp *http.Response, st *forwardState) int {
	body := st.pending
	if st.total >= 0 && int64(len(body)) > st.total {
		body = body[:st.total]
	}
	status := resp.StatusCode
	if status == http.StatusPartialContent {
		status = http.StatusOK // client never saw the earlier truncated response
	}
	h := resp.Header.Clone()
	for _, k := range hopByHopRespHeaders {
		h.Del(k)
	}
	h.Del("Content-Range")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Connection", "keep-alive")
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if err := h.Write(&sb); err != nil {
		return fwdAbort
	}
	sb.WriteString("\r\n")
	hdr := sb.String()

	_ = client.SetWriteDeadline(time.Now().Add(forwardHeaderTimeout))
	if _, err := client.Write([]byte(hdr)); err != nil {
		return fwdAbort
	}
	if _, err := client.Write(body); err != nil {
		return fwdAbort
	}
	_ = client.SetWriteDeadline(time.Time{})

	st.headerSent = true
	st.relayed = int64(len(body))
	st.total = int64(len(body))
	st.closeAfter = false
	st.pending = nil
	if st.cacheKey != "" && status == http.StatusOK && len(body) <= assetCacheMaxObject {
		st.header = hdr
		st.buf = append([]byte(nil), body...)
		p.commitAssetCache(st)
	} else {
		st.cacheKey = ""
	}
	return fwdDone
}

// streamOverflowBuffered handles the rare unknown-length body that outgrows
// the reframing budget: flush what we have close-delimited and stream the
// rest raw. No cache, no resume.
func (p *MixedProxy) streamOverflowBuffered(client net.Conn, resp *http.Response, upstream net.Conn, st *forwardState, chunk []byte) int {
	st.closeAfter = true
	st.cacheKey = ""
	if _, err := writeForwardHeader(client, resp, true); err != nil {
		return fwdAbort
	}
	st.headerSent = true
	_ = client.SetWriteDeadline(time.Now().Add(forwardHeaderTimeout))
	if _, err := client.Write(st.pending); err != nil {
		return fwdAbort
	}
	if _, err := client.Write(chunk); err != nil {
		return fwdAbort
	}
	_ = client.SetWriteDeadline(time.Time{})
	st.relayed = int64(len(st.pending)) + int64(len(chunk))
	st.pending = nil
	st.total = -1
	_ = upstream.SetReadDeadline(time.Time{})
	if _, err := io.Copy(client, resp.Body); err != nil {
		return fwdAbort
	}
	return fwdDone
}

// relayForwardBody streams the response body to the client, treating a
// zero-progress window of forwardStallTimeout or a premature EOF as a
// resumable stall.
func (p *MixedProxy) relayForwardBody(client net.Conn, respBody io.Reader, upstream net.Conn, st *forwardState, skip int64) int {
	buf := proxyCopyBufferPool.Get().([]byte)
	defer proxyCopyBufferPool.Put(buf)
	for {
		if st.total >= 0 && st.relayed >= st.total {
			p.commitAssetCache(st)
			return fwdDone
		}
		_ = upstream.SetReadDeadline(time.Now().Add(forwardStallTimeout))
		n, err := respBody.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if skip > 0 {
				drop := skip
				if drop > int64(n) {
					drop = int64(n)
				}
				chunk = chunk[drop:]
				skip -= drop
			}
			if len(chunk) > 0 {
				_ = client.SetWriteDeadline(time.Now().Add(forwardStallTimeout))
				if _, werr := client.Write(chunk); werr != nil {
					return fwdAbort
				}
				_ = client.SetWriteDeadline(time.Time{})
				st.relayed += int64(len(chunk))
				if st.cacheKey != "" {
					if int64(len(st.buf))+int64(len(chunk)) > assetCacheMaxObject {
						st.cacheKey, st.buf = "", nil // too big; stop capturing
					} else {
						st.buf = append(st.buf, chunk...)
					}
				}
			}
		}
		if err != nil {
			// A chunked stream cut mid-chunk surfaces as ErrUnexpectedEOF:
			// that's a truncation even when the total length is unknown.
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fwdRetry
			}
			if errors.Is(err, io.EOF) {
				if st.total < 0 || st.relayed >= st.total {
					// A clean EOF on a close-delimited body is the origin
					// finishing; a session cut mid-transfer surfaces as a
					// read timeout or RST, not EOF, so this is safe to cache.
					p.commitAssetCache(st)
					return fwdDone
				}
				return fwdRetry // truncated mid-body — resume on a fresh tunnel
			}
			if isTimeoutErr(err) {
				return fwdRetry // stalled — resume on a fresh tunnel
			}
			return fwdAbort
		}
	}
}

// writeForwardHeader writes the origin's response status line and headers to
// the client, normalizing connection semantics: keep-alive for known-length
// bodies, close-delimited otherwise. It returns the exact header block written
// so a cacheable response can be replayed verbatim later.
func writeForwardHeader(client net.Conn, resp *http.Response, closeAfter bool) (string, error) {
	h := resp.Header.Clone()
	for _, k := range hopByHopRespHeaders {
		h.Del(k)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %s\r\n", resp.Status)
	if closeAfter {
		h.Set("Connection", "close")
	} else {
		h.Set("Connection", "keep-alive")
		if resp.ContentLength >= 0 {
			h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}
	}
	if err := h.Write(&sb); err != nil {
		return "", err
	}
	sb.WriteString("\r\n")
	_ = client.SetWriteDeadline(time.Now().Add(forwardStallTimeout))
	_, err := client.Write([]byte(sb.String()))
	_ = client.SetWriteDeadline(time.Time{})
	return sb.String(), err
}

// forwardRaw serves a protocol-upgrade request (websocket) as a raw
// bidirectional pipe on a single upstream conn — no resume semantics.
func (p *MixedProxy) forwardRaw(client net.Conn, br *bufio.Reader, req *http.Request, body []byte, host, port string) {
	upstream, err := p.dialContext(context.Background(), "tcp", hostnameOnly(host), port)
	if err != nil {
		log.Printf("http forward dial %s:%s failed: %v", hostnameOnly(host), port, err)
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	tuneProxyConn(upstream)
	defer upstream.Close()

	outReq := req.Clone(context.Background())
	if len(body) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(body))
		outReq.ContentLength = int64(len(body))
	} else {
		outReq.Body = http.NoBody
	}
	if err := outReq.Write(upstream); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	relay(client, upstream, br)
}

// commitAssetCache stores a fully-relayed immutable asset for replay. Called
// only on the complete-body paths, so a truncated transfer can never be
// committed. The header is normalized to Content-Length + keep-alive framing:
// a close-delimited original (chunked source) would make every replay depend
// on the client seeing our FIN, which stalls behind CONNECT-tunneling
// upstreams (Stash/Clash) that propagate closes lazily.
func (p *MixedProxy) commitAssetCache(st *forwardState) {
	if st.cacheKey == "" || st.header == "" {
		return
	}
	header := normalizeCachedHeader(st.header, len(st.buf))
	p.assets.put(st.cacheKey, cachedResponse{header: header, body: st.buf, close: false})
	st.cacheKey, st.buf = "", nil
}

// normalizeCachedHeader rewrites a captured response header block to explicit
// Content-Length framing on a kept-alive connection.
func normalizeCachedHeader(header string, bodyLen int) string {
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(header, "\r\n\r\n"), "\r\n") {
		l := strings.ToLower(line)
		if strings.HasPrefix(l, "connection:") || strings.HasPrefix(l, "content-length:") ||
			strings.HasPrefix(l, "keep-alive:") || strings.HasPrefix(l, "proxy-connection:") ||
			strings.HasPrefix(l, "transfer-encoding:") {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", bodyLen)
	sb.WriteString("Connection: keep-alive\r\n\r\n")
	return sb.String()
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func hostnameOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func splitHostPortDefault(hostport, defaultPort string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	if hostport == "" {
		return "", ""
	}
	if ip := net.ParseIP(hostport); ip != nil {
		return ip.String(), defaultPort
	}
	return hostport, defaultPort
}
