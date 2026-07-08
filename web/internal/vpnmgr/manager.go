package vpnmgr

import (
	"context"
	"sort"
	"sync"
	"time"

	"corplink-web/internal/corplink"
)

// ConnState is the lifecycle state of the VPN connection.
type ConnState string

const (
	StateLoggedOut     ConnState = "logged_out"
	StateLoggedIn      ConnState = "logged_in"
	StateConnecting    ConnState = "connecting"
	StateConnected     ConnState = "connected"
	StateDisconnecting ConnState = "disconnecting"
)

// WireGuard initiators normally rekey after 120s and retry for roughly another
// 90s before giving up. Treating a 90s-old latest-handshake as dead interrupts
// healthy idle tunnels before WireGuard's own rekey window has elapsed.
const handshakeStaleAfter = 210 * time.Second
const handshakeStaleAfterSec = int64(handshakeStaleAfter / time.Second)

// rxStallAfter is how long real outbound traffic may keep flowing with zero real
// inbound bytes before we treat the tunnel as stalled. Must be longer than
// proxyDialTimeout (15s) to avoid false positives on slow but valid dials. The
// response to a stall is a non-disruptive make-before-break refresh (swap onto a
// fresh validated tunnel, no dropped connections). Some Feilian sessions get
// their data path cut ~20s after connect by the gateway's client-integrity
// enforcement, so we rotate well inside that window while still allowing slow
// dials to complete. Demand and stall are measured from APPLICATION-level
// counters (countingConn) plus dial attempts, which exclude WireGuard keepalive
// — an idle tunnel has no outbound demand and is never rotated by this path.
const rxStallAfter = 20 * time.Second

// Status is a snapshot of the manager's current state for the UI.
type Status struct {
	State         ConnState `json:"state"`
	NeedCompany   bool      `json:"need_company"`
	CompanyName   string    `json:"company_name"`
	Username      string    `json:"username"`
	ServerID      int       `json:"server_id"`
	ServerName    string    `json:"server_name"`
	Connected     bool      `json:"connected"`
	ProxyListen   string    `json:"proxy_listen"`
	AdminRequired bool      `json:"admin_required"`
	Error         string    `json:"error,omitempty"`
}

// TrafficSample is a point-in-time traffic snapshot.
type TrafficSample struct {
	Connected   bool    `json:"connected"`
	TxBps       float64 `json:"tx_bps"`
	RxBps       float64 `json:"rx_bps"`
	TxTotal     int64   `json:"tx_total"`
	RxTotal     int64   `json:"rx_total"`
	ProxyListen string  `json:"proxy_listen"`
	Since       int64   `json:"since"` // unix seconds the connection started

	// WireGuard peer stats. WireGuard has no per-packet loss counter. The
	// staleness score below only marks clear handshake failure/timeout states;
	// a normally idle tunnel can have an older handshake timestamp.
	// HandshakeAgeSec is -1 when no handshake has ever completed.
	LastHandshake     int64   `json:"last_handshake"` // unix sec, 0 if never
	HandshakeAgeSec   int64   `json:"handshake_age_sec"`
	WgTxBytes         int64   `json:"wg_tx_bytes"` // wire-level bytes sent to peer
	WgRxBytes         int64   `json:"wg_rx_bytes"` // wire-level bytes received from peer
	HandshakeStalePct float64 `json:"handshake_stale_pct"`
	LossPct           float64 `json:"loss_pct"` // deprecated: handshake_stale_pct compatibility alias
}

// Server is a UI-facing VPN node entry.
type Server struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	EnName       string `json:"en_name"`
	IP           string `json:"ip"`
	LatencyMS    int64  `json:"latency_ms"`
	ProtocolMode int    `json:"protocol_mode"`
	Selected     bool   `json:"selected"`
}

// Manager owns the corplink client, the userspace tunnel, and the proxy. It
// serializes all state transitions behind a mutex and runs background loops for
// traffic sampling, latency probing, and handshake-timeout reconnection.
type Manager struct {
	conf   *corplink.Config
	client *corplink.Client

	mu         sync.Mutex
	state      ConnState
	lastErr    string
	device     *corplink.NetstackDevice
	proxy      *corplink.MixedProxy
	since      time.Time
	curID      int
	curName    string
	curAddress string

	// traffic sampling
	lastSampleTime time.Time
	lastRx         int64
	lastTx         int64
	txBps          float64
	rxBps          float64

	// cached WireGuard peer stats (refreshed by runSampler so Traffic() stays
	// cheap and never hits the wg-go UAPI on the UI poll path).
	lastHandshake int64
	wgTxBytes     int64
	wgRxBytes     int64

	// fake-alive tracking for the handshake watchdog, driven by APPLICATION-level
	// byte counters (countingConn) — never WireGuard's wire-level totals, which
	// keepalive keeps perpetually growing. appTxAt/appRxAt are the last times real
	// proxied payload advanced outbound/inbound. A tunnel with recent outbound
	// demand but no inbound for rxStallAfter is fake-alive; an idle tunnel (no
	// recent appTxAt) is left alone regardless of keepalive traffic.
	appTxAt time.Time
	appRxAt time.Time

	// tunnelSince is when the currently-active tunnel became live (initial connect
	// or the last make-before-break refresh swap). The handshake watchdog measures
	// its grace windows from here so a just-swapped tunnel isn't judged by the
	// previous one's silence.
	tunnelSince time.Time

	// refreshMu serializes make-before-break tunnel refreshes; lastRefreshAt
	// rate-limits them so the periodic timer and stall detector don't thrash.
	refreshMu     sync.Mutex
	lastRefreshAt time.Time

	// dialAt is the last time the proxy attempted a dial through the tunnel
	// (success or failure). Failing dials on a dead tunnel produce no app-level
	// bytes, so this is the outbound-demand signal that lets the watchdog catch a
	// tunnel that is dead enough to time out every connection.
	dialAt time.Time

	serverCache []Server
	cacheMu     sync.Mutex

	admin *adminAuth

	cancelLoops context.CancelFunc
}

// New builds a Manager around a loaded config.
func New(conf *corplink.Config) (*Manager, error) {
	client, err := corplink.NewClient(conf)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		conf:   conf,
		client: client,
		state:  StateLoggedOut,
		admin:  newAdminAuth(conf),
	}
	if conf.Server != "" {
		// a persisted session may already be logged in; the first servers/state
		// call will downgrade to logged_out if the session is stale.
		m.state = StateLoggedIn
	}
	return m, nil
}

// Client exposes the underlying protocol client (for login handlers).
func (m *Manager) Client() *corplink.Client { return m.client }

// Config returns the shared config.
func (m *Manager) Config() *corplink.Config { return m.conf }

// Admin returns the admin auth gate.
func (m *Manager) Admin() *adminAuth { return m.admin }

// SetLoggedIn marks the session logged in (called after a successful login).
func (m *Manager) SetLoggedIn() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateLoggedOut {
		m.state = StateLoggedIn
	}
}

// Status returns the current status snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	proxyListen := m.conf.SocksListen
	if m.proxy != nil && m.proxy.Addr() != "" {
		proxyListen = m.proxy.Addr()
	}
	// ServerID reflects the user's current selection so the UI can highlight it:
	// the live node once connected, otherwise the pinned config value.
	serverID := m.conf.VPNServerID
	if m.state == StateConnected && m.curID != 0 {
		serverID = m.curID
	}
	return Status{
		State:         m.state,
		NeedCompany:   m.conf.Server == "",
		CompanyName:   m.conf.CompanyName,
		Username:      m.conf.Username,
		ServerID:      serverID,
		ServerName:    m.curName,
		Connected:     m.state == StateConnected,
		ProxyListen:   proxyListen,
		AdminRequired: m.conf.AdminAuthEnabled,
		Error:         m.lastErr,
	}
}

// Servers returns the cached node list, probing latencies if requested.
func (m *Manager) Servers(ctx context.Context, probe bool) ([]Server, error) {
	vpns, err := m.client.ListVPN(ctx)
	if err != nil {
		if corplink.IsLoggedOut(err) {
			m.setState(StateLoggedOut, err.Error())
		}
		return nil, err
	}
	if probe {
		vpns = m.client.ProbeLatencies(ctx, vpns)
	}
	out := make([]Server, 0, len(vpns))
	m.mu.Lock()
	pinned := m.conf.VPNServerID
	m.mu.Unlock()
	for _, v := range vpns {
		out = append(out, Server{
			ID:           v.ID,
			Name:         v.Name,
			EnName:       v.EnName,
			IP:           v.IP,
			LatencyMS:    v.LatencyMS,
			ProtocolMode: v.ProtocolMode,
			Selected:     v.ID == pinned,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		li, lj := out[i].LatencyMS, out[j].LatencyMS
		// unprobed (0) and timeouts (-1) sink below real latencies
		ki := sortKey(li)
		kj := sortKey(lj)
		return ki < kj
	})
	m.cacheMu.Lock()
	m.serverCache = out
	m.cacheMu.Unlock()
	return out, nil
}

func sortKey(latency int64) int64 {
	switch {
	case latency > 0:
		return latency
	case latency == 0:
		return 1 << 40 // unprobed
	default:
		return 1 << 50 // timeout
	}
}

func (m *Manager) setState(s ConnState, errMsg string) {
	m.mu.Lock()
	m.state = s
	m.lastErr = errMsg
	m.mu.Unlock()
}

// Traffic returns the latest traffic sample.
func (m *Manager) Traffic() TrafficSample {
	m.mu.Lock()
	defer m.mu.Unlock()
	sample := TrafficSample{
		Connected:   m.state == StateConnected,
		TxBps:       m.txBps,
		RxBps:       m.rxBps,
		ProxyListen: m.conf.SocksListen,
	}
	if m.proxy != nil && m.proxy.Addr() != "" {
		sample.ProxyListen = m.proxy.Addr()
	}
	if m.device != nil {
		sample.RxTotal = m.lastRx
		sample.TxTotal = m.lastTx
		sample.LastHandshake = m.lastHandshake
		sample.WgTxBytes = m.wgTxBytes
		sample.WgRxBytes = m.wgRxBytes
		if m.lastHandshake > 0 {
			sample.HandshakeAgeSec = int64(time.Since(time.Unix(m.lastHandshake, 0)).Seconds())
		} else {
			sample.HandshakeAgeSec = -1
		}
		sample.HandshakeStalePct = handshakeStalenessFromAge(sample.HandshakeAgeSec)
		sample.LossPct = sample.HandshakeStalePct
	}
	if !m.since.IsZero() {
		sample.Since = m.since.Unix()
	}
	return sample
}

// handshakeStalenessFromAge converts WireGuard handshake age into a coarse
// 0/100 timeout flag. WireGuard's latest-handshake timestamp is not refreshed
// continuously on a healthy idle tunnel, so intermediate ages should not be
// presented as a gradually degrading link. age == -1 means no handshake has
// ever completed.
func handshakeStalenessFromAge(ageSec int64) float64 {
	if ageSec < 0 {
		return 100
	}
	if ageSec >= handshakeStaleAfterSec {
		return 100
	}
	return 0
}
