package conn

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func Equal[T int](t *testing.T, a T, b T) {
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
}

func TestReqLen(t *testing.T) {
	var l reqLen
	l.FromLen(0)
	Equal(t, l.Len(), 0)
	l.FromLen(123456789)
	Equal(t, l.Len(), 123456789)
	l.FromLen(65535)
	Equal(t, l.Len(), 65535)
	l.FromLen(0xFFFFFFFF)
	Equal(t, l.Len(), 0xFFFFFFFF)
}

// TestTcpBindSetDialer verifies that a custom dialer (e.g. fu-corplink's
// upstream-proxy dialer) is actually used by getConn, and that nil restores
// direct dialing. This guards the coexistence-with-TUN-VPN fix.
func TestTcpBindSetDialer(t *testing.T) {
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

	var called bool
	var mu sync.Mutex
	customDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		called = true
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	bind := NewTCPBind().(*TcpBind)
	bind.SetDialer(customDial)
	// handleConn needs recvChan/closeChan which Open normally initializes; set
	// them up so getConn -> handleConn doesn't panic during this dial test.
	bind.recvChan = make(chan *recvData, 8)
	bind.closeChan = make(chan struct{})
	defer close(bind.closeChan)

	ep, err := bind.ParseEndpoint(target.Addr().String())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	state, err := bind.getConn(ep)
	if err != nil {
		t.Fatalf("getConn: %v", err)
	}
	defer state.conn.Close()
	mu.Lock()
	if !called {
		t.Fatal("custom dialer was not invoked")
	}
	mu.Unlock()

	payload := []byte("wg-via-dialer")
	if _, err := state.conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = state.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(state.conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: %q != %q", buf, payload)
	}

	// nil restores direct dialing without panicking and keeps a non-nil default.
	bind.SetDialer(nil)
	if bind.dial == nil {
		t.Fatal("dial should fall back to directTCPDial after nil, not stay nil")
	}
}
