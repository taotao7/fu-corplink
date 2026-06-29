package conn

import (
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/common"
)

var (
	_ Bind = (*TcpBind)(nil)
)

// MaxSegmentSize ref: device.MaxSegmentSize, we choose the max
const MaxSegmentSize = 65535

const tcpReceiveQueueSize = 1024

// tcpDialer dials a TCP connection to the peer endpoint. Defaults to a direct
// net.DialTCP; replaced with an upstream-proxy dialer when fu-corplink routes
// its transport through a proxy (so the WG TCP tunnel avoids the host's TUN).
type tcpDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// syscallConn is implemented by raw socket-backed connections (*net.TCPConn,
// *net.UDPConn) so fwmark/sockopt control works when present, and is skipped
// for proxied wrappers that have no underlying fd.
type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func NewTCPBind() Bind {
	return &TcpBind{
		dial: directTCPDial,
		dataPool: sync.Pool{
			New: func() any {
				data := &recvData{
					buff: make([]byte, MaxSegmentSize),
				}
				return data
			},
		},
	}
}

// directTCPDial is the default transport dialer (no proxy).
func directTCPDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

type TcpBind struct {
	connMu     sync.Mutex
	tcpConnMap common.SyncMap[string, *tcpConnState]
	listener   *net.TCPListener

	// dial overrides how outbound TCP connections to peers are established.
	// When nil, connections are dialed directly via net.DialTCP.
	dial tcpDialer

	dataPool  sync.Pool
	recvChan  chan *recvData
	closeChan chan struct{}
}

type tcpConnState struct {
	conn    net.Conn
	writeMu sync.Mutex
}

type reqLen [4]byte

func (l *reqLen) Len() int {
	return int(l[0]) + int(l[1])<<8 + int(l[2])<<16 + int(l[3])<<24
}

func (l *reqLen) FromLen(len int) {
	l[0] = byte(len & 0xff)
	l[1] = byte(len >> 8 & 0xff)
	l[2] = byte(len >> 16 & 0xff)
	l[3] = byte(len >> 24 & 0xff)
}

type recvData struct {
	len      [4]byte
	buff     []byte
	size     int
	endpoint Endpoint
}

func (t *TcpBind) makeReceive() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if len(bufs) == 0 {
			return 0, nil
		}

		readOne := func(data *recvData) {
			sizes[n] = data.size
			copy(bufs[n], data.buff[:sizes[n]])
			eps[n] = data.endpoint
			t.dataPool.Put(data)
			n++
		}

		select {
		case <-t.closeChan:
			return 0, net.ErrClosed
		case data := <-t.recvChan:
			if data == nil {
				return 0, nil
			}
			readOne(data)
		}

		for n < len(bufs) {
			select {
			case data := <-t.recvChan:
				if data == nil {
					return n, nil
				}
				readOne(data)
			default:
				return n, nil
			}
		}
		return n, nil
	}
}

func (t *TcpBind) handleConn(state *tcpConnState, endpoint Endpoint) {
	go func() {
		conn := state.conn
		tuneTCPConn(conn)
		var readErr error
		defer func() {
			t.deleteConn(endpoint, state)
			_ = conn.Close()
			// Don't log on an orderly shutdown of the whole bind; only surface
			// mid-life drops of the peer connection, which are the interesting
			// events when debugging a tunnel going dark.
			select {
			case <-t.closeChan:
			default:
				log.Printf("tcp-bind: transport conn to %s closed: %v", endpoint.DstToString(), readErr)
			}
		}()
		for {
			data := t.dataPool.Get().(*recvData)
			// read uint32 size header
			_, err := io.ReadFull(conn, data.len[:])
			if err != nil {
				readErr = err
				t.dataPool.Put(data)
				return
			}
			l := reqLen(data.len)
			size := l.Len()
			if size <= 0 || size > MaxSegmentSize {
				readErr = io.ErrUnexpectedEOF
				t.dataPool.Put(data)
				return
			}
			// read real data
			n, err := io.ReadFull(conn, data.buff[:size])
			if err != nil {
				readErr = err
				t.dataPool.Put(data)
				return
			}
			if n != size {
				t.dataPool.Put(data)
				continue
			}
			data.size = size
			data.endpoint = endpoint
			select {
			case <-t.closeChan:
				t.dataPool.Put(data)
				return
			case t.recvChan <- data:
			}
		}
	}()
}

func (t *TcpBind) deleteConn(endpoint Endpoint, state *tcpConnState) {
	key := endpoint.DstToString()
	if current, ok := t.tcpConnMap.Load(key); ok && current == state {
		t.tcpConnMap.Delete(key)
	}
}

// tuneTCPConn applies low-latency/aggressive-keepalive tuning to a connection.
// Real *net.TCPConns get the full treatment; proxied wrappers get whatever the
// socket layer allows.
func tuneTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		// Aggressive keepalive so a silently-dropped peer connection (e.g. an NAT
		// idle-timeout on the upstream gateway) is detected within ~25s. The
		// default Linux probe schedule (idle + 9*75s) takes ~11min to declare the
		// socket dead — far past WireGuard's RejectAfterTime (180s), after which
		// the whole session is void and the tunnel goes dark. Idle 10s + 5s*3
		// probes reclaims the dead conn well before that, so getConn redials a
		// fresh TCP connection and the rekey handshake lands on a live socket.
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   true,
			Idle:     10 * time.Second,
			Interval: 5 * time.Second,
			Count:    3,
		})
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
		return
	}
	// best-effort for proxied connections
	type noDelayer interface{ SetNoDelay(bool) error }
	if c, ok := conn.(noDelayer); ok {
		_ = c.SetNoDelay(true)
	}
	type keepAliveSetter interface {
		SetKeepAliveConfig(net.KeepAliveConfig) error
	}
	if c, ok := conn.(keepAliveSetter); ok {
		_ = c.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   true,
			Idle:     10 * time.Second,
			Interval: 5 * time.Second,
			Count:    3,
		})
	}
	type readBufferSetter interface{ SetReadBuffer(int) error }
	if c, ok := conn.(readBufferSetter); ok {
		_ = c.SetReadBuffer(4 << 20)
	}
	type writeBufferSetter interface{ SetWriteBuffer(int) error }
	if c, ok := conn.(writeBufferSetter); ok {
		_ = c.SetWriteBuffer(4 << 20)
	}
}

func (t *TcpBind) accept() {
	for {
		conn, err := t.listener.AcceptTCP()
		if err != nil {
			return
		}
		tuneTCPConn(conn)
		addrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &StdNetEndpoint{AddrPort: addrPort}
		state := &tcpConnState{conn: conn}
		t.tcpConnMap.Store(endpoint.DstToString(), state)
		t.handleConn(state, endpoint)
	}
}

func (t *TcpBind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	t.recvChan = make(chan *recvData, tcpReceiveQueueSize)
	t.closeChan = make(chan struct{})

	t.listener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	go t.accept()
	fn := t.makeReceive()
	return []ReceiveFunc{fn}, port, nil
}

func (t *TcpBind) Close() error {
	var err error
	t.tcpConnMap.Range(func(endpoint string, v *tcpConnState) bool {
		e := v.conn.Close()
		if e != nil {
			err = e
		}
		return true
	})
	if t.listener != nil {
		_ = t.listener.Close()
	}
	if t.closeChan != nil {
		close(t.closeChan)
	}
	return err
}

func (t *TcpBind) getConn(endpoint Endpoint) (*tcpConnState, error) {
	key := endpoint.DstToString()
	state, ok := t.tcpConnMap.Load(key)
	if ok {
		return state, nil
	}

	t.connMu.Lock()
	defer t.connMu.Unlock()
	state, ok = t.tcpConnMap.Load(key)
	if ok {
		return state, nil
	}

	ip := make(net.IP, net.IPv6len)
	if endpoint.DstIP().Is6() {
		as16 := endpoint.DstIP().As16()
		copy(ip, as16[:])
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ip, as4[:])
		ip = ip[:4]
	}
	addr := &net.TCPAddr{
		IP:   ip,
		Port: int(endpoint.(*StdNetEndpoint).Port()),
	}
	dial := t.dial
	if dial == nil {
		dial = directTCPDial
	}
	nc, err := dial(context.Background(), "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	tuneTCPConn(nc)
	state = &tcpConnState{conn: nc}
	t.tcpConnMap.Store(key, state)
	log.Printf("tcp-bind: dialed new transport conn to %s", key)
	t.handleConn(state, endpoint)
	return state, nil
}

func (t *TcpBind) Send(bufs [][]byte, endpoint Endpoint) error {
	state, err := t.getConn(endpoint)
	if err != nil {
		return err
	}
	lens := make([]reqLen, len(bufs))
	buffers := make(net.Buffers, 0, len(bufs)*2)
	for i, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		lens[i].FromLen(len(buf))
		buffers = append(buffers, lens[i][:], buf)
	}
	if len(buffers) == 0 {
		return nil
	}
	state.writeMu.Lock()
	_, err = buffers.WriteTo(state.conn)
	state.writeMu.Unlock()
	if err != nil {
		t.deleteConn(endpoint, state)
		_ = state.conn.Close()
		return err
	}
	return nil
}

func (t *TcpBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

// SetDialer overrides how outbound TCP connections to peers are dialed. Pass nil
// to restore direct dialing. Used by fu-corplink to route the WireGuard TCP
// transport through an upstream HTTP/SOCKS5 proxy so it isn't captured by a
// host-layer TUN VPN. Must be called before Open.
func (t *TcpBind) SetDialer(d tcpDialer) {
	if d == nil {
		t.dial = directTCPDial
		return
	}
	t.dial = d
}

func (t *TcpBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}
