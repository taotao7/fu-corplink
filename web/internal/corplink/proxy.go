package corplink

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Dialer dials TCP connections to a host:port, typically through the tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ProxyAuth optionally gates the proxy with username/password credentials
// (applied to SOCKS5 via RFC 1929 and to HTTP via Proxy-Authorization Basic).
type ProxyAuth struct {
	Username string
	Password string
}

func (a *ProxyAuth) required() bool { return a != nil && a.Username != "" }

// MixedProxy serves HTTP CONNECT, plain HTTP forward, and SOCKS5 on a single
// listener, auto-detecting the protocol from the first byte (like mihomo's
// mixed-port). All upstream connections are dialed via the provided Dialer so
// traffic egresses through the VPN tunnel; DNS is resolved in-tunnel.
type MixedProxy struct {
	dialer Dialer
	auth   *ProxyAuth

	ln     net.Listener
	closed chan struct{}
	once   sync.Once
}

// NewMixedProxy creates a proxy that dials via dialer. auth may be nil.
func NewMixedProxy(dialer Dialer, auth *ProxyAuth) *MixedProxy {
	return &MixedProxy{dialer: dialer, auth: auth, closed: make(chan struct{})}
}

// ListenAndServe binds listenAddr and serves until Close is called.
func (p *MixedProxy) ListenAndServe(listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen proxy %s: %w", listenAddr, err)
	}
	p.ln = ln
	go p.acceptLoop()
	return nil
}

// Addr returns the actual listen address (useful when binding :0).
func (p *MixedProxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Close stops the proxy.
func (p *MixedProxy) Close() {
	p.once.Do(func() {
		close(p.closed)
		if p.ln != nil {
			_ = p.ln.Close()
		}
	})
}

func (p *MixedProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
				continue
			}
		}
		go p.handle(conn)
	}
}

func (p *MixedProxy) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(client)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	// SOCKS5 begins with version byte 0x05; anything else is treated as HTTP.
	if first[0] == 0x05 {
		p.handleSocks5(client, br)
		return
	}
	p.handleHTTP(client, br)
}

// --- SOCKS5 (RFC 1928 / 1929) -------------------------------------------

func (p *MixedProxy) handleSocks5(client net.Conn, br *bufio.Reader) {
	// greeting: VER NMETHODS METHODS...
	ver, _ := br.ReadByte()
	if ver != 0x05 {
		return
	}
	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	if p.auth.required() {
		if !containsByte(methods, 0x02) {
			_, _ = client.Write([]byte{0x05, 0xff}) // no acceptable methods
			return
		}
		_, _ = client.Write([]byte{0x05, 0x02}) // username/password
		if !p.socks5Auth(client, br) {
			return
		}
	} else {
		_, _ = client.Write([]byte{0x05, 0x00}) // no auth
	}

	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	if header[1] != 0x01 { // only CONNECT
		socks5Reply(client, 0x07) // command not supported
		return
	}

	host, err := readSocksAddr(br, header[3])
	if err != nil {
		socks5Reply(client, 0x08) // address type not supported
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	upstream, err := p.dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		socks5Reply(client, 0x05) // connection refused
		return
	}
	defer upstream.Close()
	socks5Reply(client, 0x00) // succeeded

	_ = client.SetDeadline(time.Time{})
	relay(client, upstream, br)
}

func (p *MixedProxy) socks5Auth(client net.Conn, br *bufio.Reader) bool {
	// VER ULEN UNAME PLEN PASSWD
	ver, _ := br.ReadByte()
	if ver != 0x01 {
		return false
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return false
	}
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(br, uname); err != nil {
		return false
	}
	plen, err := br.ReadByte()
	if err != nil {
		return false
	}
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(br, passwd); err != nil {
		return false
	}
	ok := string(uname) == p.auth.Username && string(passwd) == p.auth.Password
	if ok {
		_, _ = client.Write([]byte{0x01, 0x00})
	} else {
		_, _ = client.Write([]byte{0x01, 0x01})
	}
	return ok
}

func readSocksAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03: // domain
		l, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", errors.New("unsupported address type")
	}
}

func socks5Reply(w io.Writer, code byte) {
	// VER REP RSV ATYP BND.ADDR(0.0.0.0) BND.PORT(0)
	_, _ = w.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func containsByte(b []byte, target byte) bool {
	for _, x := range b {
		if x == target {
			return true
		}
	}
	return false
}

// relay pipes data bidirectionally between client and upstream. The client's
// buffered reader is used so any bytes already buffered are not lost.
func relay(client net.Conn, upstream net.Conn, clientBuf *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientBuf)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}
