package vpnmgr

import (
	"context"
	"errors"
	"fmt"
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

	// A 2FA code is needed unless a TOTP secret is configured or an SSO login
	// already verified. Require an explicit otp only when we can't generate one.
	if otp == "" && !m.client.HasOTPSecret() && !isTpsPlatform(m.conf.Platform) {
		return ErrNeedOTP
	}

	info, err := m.client.FetchPeerInfo(ctx, otp)
	if err != nil {
		if corplink.IsLoggedOut(err) {
			m.setState(StateLoggedOut, err.Error())
		}
		return err
	}

	wgConf, err := m.client.BuildWgConf(*node, info)
	if err != nil {
		return err
	}

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
}

// runHandshakeWatch tears down the connection if the WireGuard handshake goes
// stale (no handshake for over 5 minutes), mirroring the upstream client.
func (m *Manager) runHandshakeWatch(ctx context.Context, wgConf *corplink.WgConf) {
	const timeout = 5 * time.Minute
	ticker := time.NewTicker(time.Minute)
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
				m.setState(StateLoggedIn, "wireguard handshake timed out")
				m.teardown()
				return
			}
		}
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
