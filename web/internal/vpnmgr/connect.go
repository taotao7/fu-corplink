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

	device, err := corplink.StartNetstack(wgConf)
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
	m.lastRx, m.lastTx = rx, tx
	m.lastSampleTime = now

	// refresh cached WireGuard peer stats so Traffic() never blocks on the
	// wg-go UAPI. Reads are cheap (one IpcGet per second).
	ps := m.device.PeerStats()
	m.lastHandshake = ps.LastHandshakeSec
	m.wgTxBytes = ps.TxBytes
	m.wgRxBytes = ps.RxBytes
}

// runHandshakeWatch reconnects the tunnel if the WireGuard handshake goes stale.
// In TCP-bind mode the peer can drop an idle connection within a few minutes,
// after which all in-tunnel traffic (including DNS) silently fails while the UI
// still shows "connected". We poll the last-handshake time and, once it exceeds
// the timeout, transparently re-establish the tunnel so the connection self-heals
// instead of stranding the user until they reconnect by hand.
func (m *Manager) runHandshakeWatch(ctx context.Context, wgConf *corplink.WgConf) {
	const timeout = 90 * time.Second
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			dev := m.device
			m.mu.Unlock()
			if dev == nil {
				return
			}
			last := dev.LastHandshake()
			if last == 0 {
				continue
			}
			if time.Since(time.Unix(last, 0)) > timeout {
				// reconnect runs the teardown that cancels this loop's ctx, so
				// returning here lets the freshly-spawned watcher take over.
				go m.reconnect()
				return
			}
		}
	}
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
