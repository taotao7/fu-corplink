package vpnmgr

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"corplink-web/internal/corplink"
)

// ErrNeedOTP indicates a 2FA code is required to complete the connection.
var ErrNeedOTP = errors.New("otp required")

// Connect establishes the VPN tunnel and starts the proxy. serverID, when
// non-zero, pins the node for this connection (and is persisted). otp, when
// non-empty, supplies a 2FA code; if a code is required and none is available,
// ErrNeedOTP is returned so the caller can prompt for one.
func (m *Manager) Connect(ctx context.Context, serverID int, otp string) error {
	m.mu.Lock()
	if m.state == StateConnected || m.state == StateConnecting {
		m.mu.Unlock()
		return fmt.Errorf("already %s", m.state)
	}
	m.state = StateConnecting
	m.lastErr = ""
	if serverID != 0 {
		m.conf.VPNServerID = serverID
	}
	m.mu.Unlock()
	_ = m.conf.Save()

	if err := m.connectReal(ctx, otp); err != nil {
		m.setState(StateLoggedIn, err.Error())
		m.teardown()
		return err
	}
	return nil
}

func (m *Manager) connectReal(ctx context.Context, otp string) error {
	vpns, err := m.client.ListVPN(ctx)
	if err != nil {
		if corplink.IsLoggedOut(err) {
			m.setState(StateLoggedOut, err.Error())
		}
		return err
	}

	node, err := m.client.SelectVPN(ctx, vpns)
	if err != nil {
		return err
	}

	// Don't pre-gate on 2FA. Most accounts either have no 2FA at all (an empty
	// code connects fine) or have a TOTP secret we generate automatically. Try
	// the handshake first; only prompt for a code if the server actually
	// rejects it for an OTP-related reason.
	info, err := m.client.FetchPeerInfo(ctx, otp)
	if err != nil {
		if corplink.IsLoggedOut(err) {
			m.setState(StateLoggedOut, err.Error())
			return err
		}
		if otp == "" && !m.client.HasOTPSecret() && looksLikeOTPError(err) {
			return ErrNeedOTP
		}
		return err
	}

	wgConf, err := m.client.BuildWgConf(*node, info)
	if err != nil {
		return err
	}
	log.Printf(
		"wireguard config: protocol=%d endpoint=%s address=%s ipv6=%t allowed_ips=%d dns=%q",
		wgConf.Protocol,
		wgConf.PeerAddress,
		wgConf.Address,
		wgConf.Address6 != "",
		len(wgConf.AllowedIPs),
		wgConf.DNS,
	)

	device, err := corplink.StartNetstackWithProxy(wgConf, m.client.UpstreamProxy())
	if err != nil {
		return err
	}

	var auth *corplink.ProxyAuth
	if m.conf.ProxyAuthEnabled && m.conf.ProxyUsername != "" {
		auth = &corplink.ProxyAuth{Username: m.conf.ProxyUsername, Password: m.conf.ProxyPassword}
	}
	proxy := corplink.NewMixedProxy(device, auth)
	if err := proxy.ListenAndServe(m.conf.SocksListen); err != nil {
		device.Close()
		return err
	}

	// report the connection to the node (best-effort)
	mode := routeModeReport(m.conf.RouteModeOrDefault())
	if err := m.client.ReportDevice(ctx, wgConf.Address, mode, false); err != nil {
		// non-fatal: the tunnel is up regardless
		_ = err
	}

	m.mu.Lock()
	m.device = device
	m.proxy = proxy
	m.since = time.Now()
	m.curID = node.ID
	m.curName = node.EnName
	m.curAddress = wgConf.Address
	m.lastRx, m.lastTx = 0, 0
	m.lastHandshake = 0
	m.wgTxBytes, m.wgRxBytes = 0, 0
	m.lastSampleTime = time.Now()
	m.state = StateConnected
	m.lastErr = ""
	loopCtx, cancel := context.WithCancel(context.Background())
	m.cancelLoops = cancel
	m.mu.Unlock()

	go m.runSampler(loopCtx)
	go m.runReporter(loopCtx, wgConf)
	go m.runHandshakeWatch(loopCtx, wgConf)
	return nil
}

// Disconnect tears down the tunnel and proxy, reporting the disconnect.
func (m *Manager) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	if m.state != StateConnected && m.state != StateConnecting {
		m.mu.Unlock()
		return nil
	}
	m.state = StateDisconnecting
	address := ""
	if m.device != nil {
		address = m.curAddress
	}
	m.mu.Unlock()

	// best-effort disconnect report
	mode := routeModeReport(m.conf.RouteModeOrDefault())
	if address != "" {
		_ = m.client.ReportDevice(ctx, address, mode, true)
	}

	m.teardown()
	m.setState(StateLoggedIn, "")
	return nil
}

// teardown stops loops, the proxy and the device.
func (m *Manager) teardown() {
	m.mu.Lock()
	cancel := m.cancelLoops
	proxy := m.proxy
	device := m.device
	m.proxy = nil
	m.device = nil
	m.cancelLoops = nil
	m.since = time.Time{}
	m.txBps, m.rxBps = 0, 0
	m.lastHandshake = 0
	m.wgTxBytes, m.wgRxBytes = 0, 0
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if proxy != nil {
		proxy.Close()
	}
	if device != nil {
		device.Close()
	}
}

// runSampler periodically samples tunnel byte counters to compute live rates.
func (m *Manager) runSampler(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sampleOnce()
		}
	}
}

func (m *Manager) sampleOnce() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.device == nil {
		return
	}
	rx, tx := m.device.Transfer()
	now := time.Now()
	dt := now.Sub(m.lastSampleTime).Seconds()
	if dt > 0 {
		m.rxBps = float64(rx-m.lastRx) / dt
		m.txBps = float64(tx-m.lastTx) / dt
	}
	// Record when real (application-level) traffic last advanced, for the
	// fake-alive watchdog. These countingConn totals exclude WireGuard keepalive,
	// so an idle tunnel shows no outbound demand and is never falsely reconnected.
	if tx > m.lastTx {
		m.appTxAt = now
	}
	if rx > m.lastRx {
		m.appRxAt = now
	}
	m.lastRx, m.lastTx = rx, tx
	m.lastSampleTime = now
	m.dialAt = m.device.LastDialActivity()

	// refresh cached WireGuard peer stats so Traffic() never blocks on the
	// wg-go UAPI. Reads are cheap (one IpcGet per second). These wire-level
	// counters are for the UI only; the watchdog uses the app-level times above.
	ps := m.device.PeerStats()
	m.lastHandshake = ps.LastHandshakeSec
	m.wgTxBytes = ps.TxBytes
	m.wgRxBytes = ps.RxBytes
}

// runReporter periodically refreshes the device connection status with the
// selected node. Some CorpLink gateways expire node-side session state if the
// mobile client stops reporting after the initial connect, even though the
// WireGuard transport keepalive is still running.
func (m *Manager) runReporter(ctx context.Context, wgConf *corplink.WgConf) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	mode := routeModeReport(m.conf.RouteModeOrDefault())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.client.ReportDevice(ctx, wgConf.Address, mode, false); err != nil {
				log.Printf("wireguard report failed: %v", err)
			}
		}
	}
}

// runHandshakeWatch reconnects the tunnel when it detects the data path is dead.
// It uses two complementary signals, because CorpLink gateways can keep the
// WireGuard handshake alive while silently dropping every data packet:
//
//  1. Handshake stale: latest-handshake timestamp older than handshakeStaleAfter.
//     Catches a peer that has stopped responding entirely (TCP conn dropped,
//     gateway gone, NAT idle-timeout).
//
//  2. RX stall (fake-alive): we keep transmitting (wgTxBytes growing) but have
//     received nothing (wgRxBytes flat) for longer than rxStallAfter. This is
//     the signature of a gateway that answers handshakes yet drops data, which a
//     handshake-only check can never see. An idle tunnel with no outbound demand
//     is left alone.
//
// Stats come from runSampler's per-second PeerStats() cache, so this loop never
// hits the wg-go UAPI itself.
func (m *Manager) runHandshakeWatch(ctx context.Context, wgConf *corplink.WgConf) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	startedAt := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			dev := m.device
			if dev == nil {
				m.mu.Unlock()
				return
			}
			last := m.lastHandshake
			appTxAt := m.appTxAt
			appRxAt := m.appRxAt
			dialAt := m.dialAt
			m.mu.Unlock()

			now := time.Now()
			log.Printf("handshake watch: last_handshake=%d app_tx_ago=%s app_rx_ago=%s dial_ago=%s",
				last, ageString(appTxAt, now), ageString(appRxAt, now), ageString(dialAt, now))

			reason := reconnectReason(reconnectInputs{
				lastHandshake: last,
				startedAt:     startedAt,
				appTxAt:       appTxAt,
				appRxAt:       appRxAt,
				dialAt:        dialAt,
				now:           now,
			})
			if reason != "" {
				log.Printf("reconnect: %s", reason)
				go m.reconnect()
				return
			}
		}
	}
}

// reconnectInputs bundles the state a reconnect decision is made from.
type reconnectInputs struct {
	lastHandshake int64     // unix seconds, 0 if never
	startedAt     time.Time // tunnel start, for the never-handshaked grace window
	appTxAt       time.Time // last time real outbound app bytes were sent; zero if never
	appRxAt       time.Time // last time real inbound app bytes arrived; zero if never
	dialAt        time.Time // last dial attempt through the tunnel (success or fail); zero if never
	now           time.Time
}

// reconnectReason returns a non-empty reason string when the tunnel should be
// torn down and re-established, or "" when it looks healthy. Extracted from the
// watchdog loop so the decision is unit-testable.
func reconnectReason(in reconnectInputs) string {
	// Signal 1: handshake stale. A handshake older than handshakeStaleAfter (or a
	// never-completed one past the same grace window) means the peer has stopped
	// responding entirely.
	if in.lastHandshake == 0 {
		if in.now.Sub(in.startedAt) > handshakeStaleAfter {
			return fmt.Sprintf("no handshake within %s of tunnel start", handshakeStaleAfter)
		}
		// fall through: a never-handshaked tunnel that is already failing dials
		// shouldn't have to wait the full grace window (see signal 2).
	} else if handshakeAge := in.now.Sub(time.Unix(in.lastHandshake, 0)); handshakeAge > handshakeStaleAfter {
		return fmt.Sprintf("handshake stale (age %s > %s)", handshakeAge, handshakeStaleAfter)
	}

	// Signal 2: dead under load. There is recent outbound demand — real bytes
	// went out (appTxAt) OR the proxy attempted a dial (dialAt, which times out
	// on a dead tunnel and never becomes countingConn bytes) — yet no real
	// inbound bytes have arrived for rxStallAfter. This catches a gateway that
	// keeps answering WireGuard handshakes while silently dropping all data
	// (session revoked / fake-alive), including the hard case where every dial
	// times out. WireGuard keepalive touches none of these app-level signals, so
	// a truly idle tunnel (no recent demand) is never torn down here.
	recentDemand := within(in.appTxAt, in.now, rxStallAfter) || within(in.dialAt, in.now, rxStallAfter)
	if recentDemand {
		// How long inbound has been silent. For a tunnel that never received any
		// app bytes, measure from its start so a healthy just-connected tunnel
		// with an in-flight first request isn't torn down before it can reply.
		inboundSilent := in.now.Sub(in.startedAt)
		if !in.appRxAt.IsZero() {
			inboundSilent = in.now.Sub(in.appRxAt)
		}
		if inboundSilent > rxStallAfter {
			return fmt.Sprintf("dead under load - outbound demand but no inbound for %s", inboundSilent)
		}
	}
	return ""
}

// within reports whether t is non-zero and less than d ago relative to now.
func within(t, now time.Time, d time.Duration) bool {
	return !t.IsZero() && now.Sub(t) < d
}

// ageString renders a duration-since in a compact form for log lines, tolerating
// the zero value (never observed).
func ageString(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return now.Sub(t).Round(time.Second).String()
}

// reconnect tears down the current tunnel and re-establishes it in place,
// preserving the selected node. It is triggered by the handshake watchdog when
// the tunnel goes stale. OTP is left empty: accounts with no 2FA reconnect
// cleanly and accounts with a stored TOTP secret regenerate codes automatically;
// only manual-OTP accounts fall back to needing a user-initiated reconnect.
func (m *Manager) reconnect() {
	m.mu.Lock()
	if m.state != StateConnected {
		// a manual disconnect/reconnect raced us; let it win.
		m.mu.Unlock()
		return
	}
	m.state = StateConnecting
	m.mu.Unlock()

	log.Printf("wireguard handshake stale; reconnecting tunnel")
	m.teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.connectReal(ctx, ""); err != nil {
		log.Printf("wireguard reconnect failed: %v", err)
		m.setState(StateLoggedIn, "reconnect failed: "+err.Error())
		m.teardown()
	}
}

func routeModeReport(mode string) string {
	if mode == corplink.RouteModeSplit {
		return "Split"
	}
	return "Full"
}

func isTpsPlatform(platform string) bool {
	return platform == corplink.PlatformLark || platform == corplink.PlatformOIDC
}

var _ = isTpsPlatform // reserved: SSO logins skip the OTP prompt entirely

// looksLikeOTPError reports whether a FetchPeerInfo failure is the server
// asking for a 2FA code, as opposed to any other error. Matching is loose
// because the upstream API returns localized/varied messages.
func looksLikeOTPError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{"otp", "2fa", "two-factor", "two factor", "verif", "动态码", "验证码", "二次"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}
