package conn

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/common"
)

var (
	_ Bind = (*TcpBind)(nil)
)

// MaxSegmentSize ref: device.MaxSegmentSize, we choose the max
const MaxSegmentSize = 65535

const tcpReceiveQueueSize = 1024

func NewTCPBind() Bind {
	return &TcpBind{
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

type TcpBind struct {
	connMu     sync.Mutex
	tcpConnMap common.SyncMap[string, *tcpConnState]
	listener   *net.TCPListener

	dataPool  sync.Pool
	recvChan  chan *recvData
	closeChan chan struct{}
}

type tcpConnState struct {
	conn    *net.TCPConn
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
		defer func() {
			t.deleteConn(endpoint, state)
			_ = conn.Close()
		}()
		for {
			data := t.dataPool.Get().(*recvData)
			// read uint32 size header
			_, err := io.ReadFull(conn, data.len[:])
			if err != nil {
				t.dataPool.Put(data)
				return
			}
			l := reqLen(data.len)
			size := l.Len()
			if size <= 0 || size > MaxSegmentSize {
				t.dataPool.Put(data)
				return
			}
			// read real data
			n, err := io.ReadFull(conn, data.buff[:size])
			if err != nil {
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

func tuneTCPConn(conn *net.TCPConn) {
	_ = conn.SetNoDelay(true)
	// Aggressive keepalive so a silently-dropped peer connection (e.g. an NAT
	// idle-timeout on the upstream gateway) is detected within ~25s. The
	// default Linux probe schedule (idle + 9*75s) takes ~11min to declare the
	// socket dead — far past WireGuard's RejectAfterTime (180s), after which the
	// whole session is void and the tunnel goes dark. Idle 10s + 5s*3 probes
	// reclaims the dead conn well before that, so getConn redials a fresh TCP
	// connection and the rekey handshake lands on a live socket.
	_ = conn.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     10 * time.Second,
		Interval: 5 * time.Second,
		Count:    3,
	})
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
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
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	tuneTCPConn(conn)
	state = &tcpConnState{conn: conn}
	t.tcpConnMap.Store(key, state)
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

func (t *TcpBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}
