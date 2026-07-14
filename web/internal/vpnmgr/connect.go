package vpnmgr

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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
	device, wgConf, node, err := m.buildTunnel(ctx, otp)
	if err != nil {
		return err
	}
	// Validate the data path before committing, but only when no OTP handoff is
	// in play (buildLiveTunnel always uses an empty OTP on retry). For the very
	// first connect we keep the caller-supplied otp path via buildTunnel above and
	// probe once here; a dead first tunnel will be caught by the watchdog/refresher.
	probeAddr := tunnelProbeAddr(wgConf)
	pctx, pcancel := context.WithTimeout(ctx, tunnelProbeTimeout)
	if perr := device.Probe(pctx, probeAddr); perr != nil {
		log.Printf("initial tunnel data-path probe failed: %v (continuing; refresher will rotate)", perr)
	}
	pcancel()

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
	m.resetTunnelStatsLocked()
	m.state = StateConnected
	m.lastErr = ""
	loopCtx, cancel := context.WithCancel(context.Background())
	m.cancelLoops = cancel
	m.mu.Unlock()

	go m.runSampler(loopCtx)
	go m.runReporter(loopCtx)
	go m.runHandshakeWatch(loopCtx)
	go m.runRefresher(loopCtx)
	return nil
}

// buildTunnel performs the handshake exchange and brings up a fresh userspace
// WireGuard device for the selected node. It does not touch Manager state, so it
// is safe to call both for the initial connect and for a background refresh.
func (m *Manager) buildTunnel(ctx context.Context, otp string) (*corplink.NetstackDevice, *corplink.WgConf, *corplink.VPNInfo, error) {
	vpns, err := m.client.ListVPN(ctx)
	if err != nil {
		if corplink.IsLoggedOut(err) {
			m.setState(StateLoggedOut, err.Error())
		}
		return nil, nil, nil, err
	}

	node, err := m.client.SelectVPN(ctx, vpns)
	if err != nil {
		return nil, nil, nil, err
	}

	// Don't pre-gate on 2FA. Most accounts either have no 2FA at all (an empty
	// code connects fine) or have a TOTP secret we generate automatically. Try
	// the handshake first; only prompt for a code if the server actually
	// rejects it for an OTP-related reason.
	info, err := m.client.FetchPeerInfo(ctx, otp)
	if err != nil {
		if corplink.IsLoggedOut(err) {
			m.setState(StateLoggedOut, err.Error())
			return nil, nil, nil, err
		}
		if otp == "" && !m.client.HasOTPSecret() && looksLikeOTPError(err) {
			return nil, nil, nil, ErrNeedOTP
		}
		return nil, nil, nil, err
	}

	wgConf, err := m.client.BuildWgConf(*node, info)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}
	return device, wgConf, node, nil
}

// buildLiveTunnel builds a tunnel and verifies its data path works before
// returning it, retrying a few times because a freshly-handshaked CorpLink
// tunnel is sometimes dead-on-arrival (the gateway's data plane doesn't come up
// even though the handshake completed). A validated tunnel is essential for the
// refresher: swapping the proxy onto a dead tunnel would break every connection.
//
// Validation covers recently-used destinations, not just the DNS server: a new
// session's route to internal (172.16.x) services can lag its route to DNS by
// several seconds, and swapping during that gap turns every user request into a
// timeout. Early attempts therefore require a recent destination to answer;
// the final attempt relaxes to DNS-only so a service that is genuinely down
// can't block rotation forever.
func (m *Manager) buildLiveTunnel(ctx context.Context) (*corplink.NetstackDevice, *corplink.WgConf, *corplink.VPNInfo, error) {
	recentAddrs := m.recentProxyDials()
	var lastErr error
	for attempt := 0; attempt < tunnelBuildAttempts; attempt++ {
		device, wgConf, node, err := m.buildTunnel(ctx, "")
		if err != nil {
			return nil, nil, nil, err // build/handshake errors are not transient here
		}
		strict := attempt < tunnelBuildAttempts-1
		pctx, cancel := context.WithTimeout(ctx, tunnelProbeTimeout)
		err = probeTunnel(pctx, device, tunnelProbeAddr(wgConf), recentAddrs, strict)
		cancel()
		if err == nil {
			return device, wgConf, node, nil
		}
		lastErr = err
		log.Printf("new tunnel failed data-path probe (attempt %d/%d): %v", attempt+1, tunnelBuildAttempts, err)
		device.Close()
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("tunnel probe failed")
	}
	return nil, nil, nil, lastErr
}

// recentProxyDials returns destinations users recently reached through the live
// proxy, for route-convergence probing of candidate tunnels. Empty when no
// proxy is running or nothing was dialed recently.
func (m *Manager) recentProxyDials() []string {
	m.mu.Lock()
	proxy := m.proxy
	m.mu.Unlock()
	if proxy == nil {
		return nil
	}
	return proxy.RecentDialAddrs(recentProbeAddrs)
}

// recentProbeAddrs is how many recently-dialed destinations a candidate tunnel
// is probed against; one answering suffices.
const recentProbeAddrs = 3

// tunnelProbeAddr picks an in-tunnel host:port to validate the data path against
// — the tunnel's DNS server on port 53, which every CorpLink node routes.
func tunnelProbeAddr(wgConf *corplink.WgConf) string {
	dns := strings.FieldsFunc(wgConf.DNS, func(r rune) bool { return r == ',' || r == ' ' })
	if len(dns) > 0 && strings.TrimSpace(dns[0]) != "" {
		return net.JoinHostPort(strings.TrimSpace(dns[0]), "53")
	}
	return "223.5.5.5:53"
}

const (
	tunnelBuildAttempts = 4
	// Window for one probeTunnel pass: DNS plus up to recentProbeAddrs
	// destinations at probeEachTimeout each.
	tunnelProbeTimeout = 8 * time.Second
)

// resetTunnelStatsLocked zeroes the per-tunnel sampling baselines. Caller holds m.mu.
func (m *Manager) resetTunnelStatsLocked() {
	m.lastRx, m.lastTx = 0, 0
	m.lastHandshake = 0
	m.wgTxBytes, m.wgRxBytes = 0, 0
	m.lastSampleTime = time.Now()
	m.appTxAt = time.Time{}
	m.appRxAt = time.Time{}
	m.dialAt = time.Time{}
	m.tunnelSince = time.Now()
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
func (m *Manager) runReporter(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	mode := routeModeReport(m.conf.RouteModeOrDefault())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			addr := m.curAddress
			m.mu.Unlock()
			if err := m.client.ReportDevice(ctx, addr, mode, false); err != nil {
				log.Printf("wireguard report failed: %v", err)
			}
		}
	}
}

// tunnelRefreshAfter is how long a freshly-established tunnel is used before the
// refresher proactively rotates it. Some Feilian gateways enforce a client
// "integrity heartbeat" (an encrypted per-few-seconds report the official client
// sends) and silently cut the data path ~60s after connect when they don't see
// it — the /vpn/report reply is {"code":1000,"action":"alert"}. We cannot forge
// that proprietary heartbeat, so instead we make-before-break: build a brand new
// tunnel (new session, fresh cutoff budget) and hot-swap the proxy onto it just
// before the old one is due to die, so proxied connections never see the gap.
// Kept well under the observed ~60s cutoff (some sessions die sooner) so a fresh,
// data-path-validated tunnel is always ready ahead of the old one failing.
const tunnelRefreshAfter = 18 * time.Second

// runRefresher proactively rotates the tunnel before the gateway's integrity
// cutoff. It builds a new tunnel out-of-band, atomically swaps the live proxy
// onto it, then retires the old device after a short drain so in-flight
// connections on it can finish. Besides the periodic timer it also reacts to
// kicks from the proxy: a stalled/timed-out request is live proof the current
// tunnel is dead, and rotating immediately shaves the remaining timer wait off
// that request's tail latency.
func (m *Manager) runRefresher(ctx context.Context) {
	m.mu.Lock()
	proxy := m.proxy
	m.mu.Unlock()
	var kick <-chan struct{}
	if proxy != nil {
		kick = proxy.RefreshKick()
	}

	ticker := time.NewTicker(tunnelRefreshAfter)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			if err := m.refreshTunnelKicked(ctx, true); err != nil {
				log.Printf("kicked tunnel refresh failed: %v", err)
			} else {
				// A successful rotation restarts the proactive cadence.
				ticker.Reset(tunnelRefreshAfter)
			}
		case <-ticker.C:
			if err := m.refreshTunnel(ctx); err != nil {
				// Non-fatal: the handshake watchdog remains the backstop if a
				// refresh fails and the current tunnel later dies.
				log.Printf("tunnel refresh failed: %v", err)
			}
		}
	}
}

// refreshTunnel builds a replacement tunnel and hot-swaps the proxy onto it
// without dropping the listener (make-before-break). The old device is closed
// after a short drain window. Calls are serialized and rate-limited so the timer
// and stall-detector paths don't build tunnels concurrently or thrash.
func (m *Manager) refreshTunnel(ctx context.Context) error {
	return m.refreshTunnelKicked(ctx, false)
}

// refreshTunnelKicked is refreshTunnel with the kicked flag: kicked refreshes
// (a proxied request proved the tunnel dead) use a lower coalescing floor.
func (m *Manager) refreshTunnelKicked(ctx context.Context, kicked bool) error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	m.mu.Lock()
	proxy := m.proxy
	oldDevice := m.device
	oldAddress := m.curAddress
	sinceLast := time.Since(m.lastRefreshAt)
	if m.state != StateConnected || proxy == nil || oldDevice == nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	// Coalesce refreshes that land right on top of each other (e.g. stall detector
	// firing just after the periodic timer). Kicked refreshes carry live proof the
	// current tunnel is dead (a request stalled on it), so they get a lower floor:
	// suppressing them entirely would leave the stalled request waiting out the
	// rest of the periodic cycle on a proven-dead tunnel.
	floor := minRefreshInterval
	if kicked {
		floor = minKickRefreshInterval
	}
	if sinceLast < floor {
		return nil
	}

	bctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	device, wgConf, node, err := m.buildLiveTunnel(bctx)
	if err != nil {
		return err
	}

	// Swap the proxy onto the new tunnel; new connections use it immediately.
	proxy.SetTunnel(device, device)

	// Report the new session so the node marks it active.
	mode := routeModeReport(m.conf.RouteModeOrDefault())
	_ = m.client.ReportDevice(bctx, wgConf.Address, mode, false)

	m.mu.Lock()
	// A manual disconnect/reconnect may have raced us; if so, abandon the new
	// tunnel rather than resurrect a torn-down connection.
	if m.state != StateConnected || m.proxy != proxy {
		m.mu.Unlock()
		device.Close()
		return nil
	}
	m.device = device
	m.curID = node.ID
	m.curName = node.EnName
	m.curAddress = wgConf.Address
	m.resetTunnelStatsLocked()
	m.lastRefreshAt = time.Now()
	m.mu.Unlock()

	log.Printf("tunnel refreshed: new session on %s (%s)", node.EnName, wgConf.Address)

	// Drain the old tunnel until connections dialed on it finish (a large asset
	// download can easily outlive a fixed grace), then close it. Capped so a
	// wedged connection can't leak devices. Report its disconnect best-effort so
	// the node frees the session.
	go func(dev *corplink.NetstackDevice, addr string) {
		waitDrained(dev, tunnelDrainAfter, tunnelDrainMax, time.Second)
		if addr != "" {
			_ = m.client.ReportDevice(context.Background(), addr, mode, true)
		}
		dev.Close()
	}(oldDevice, oldAddress)
	return nil
}

// tunnelDrainAfter is the minimum time the previous tunnel is kept alive after
// a refresh swap; beyond it the tunnel is held only while proxied connections
// remain open on it, up to tunnelDrainMax.
const tunnelDrainAfter = 10 * time.Second

// tunnelDrainMax caps how long a retiring tunnel can be held open by in-flight
// connections before it is closed regardless (bounds device leakage). Observed
// tunnel throughput can be as low as ~5KB/s, so a large SPA bundle (~500KB+)
// needs several minutes on one connection; 90s cut such downloads mid-stream
// (browser sees ERR_INCOMPLETE_CHUNKED_ENCODING and the page white-screens).
const tunnelDrainMax = 600 * time.Second

// connCounter is the slice of NetstackDevice the drain logic needs.
type connCounter interface{ ActiveConns() int64 }

// waitDrained blocks for at least min, then keeps waiting (polling every step)
// while dev still has open proxied connections, up to max total.
func waitDrained(dev connCounter, min, max, step time.Duration) {
	deadline := time.Now().Add(max)
	time.Sleep(min)
	for dev.ActiveConns() > 0 && time.Now().Before(deadline) {
		time.Sleep(step)
	}
}

// minRefreshInterval coalesces refreshes triggered close together (periodic
// timer + stall detector) so we don't build tunnels back-to-back.
const minRefreshInterval = 8 * time.Second

// minKickRefreshInterval is the coalescing floor for proxy-kicked refreshes.
// A kick means a request is actively stalled on a proven-dead tunnel, so it
// only needs to guard against pathological thrash (kick landing right on the
// heels of a completed swap), not enforce the full periodic spacing.
const minKickRefreshInterval = 2 * time.Second

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
func (m *Manager) runHandshakeWatch(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

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
			// Measure grace windows from when the CURRENT tunnel became live (last
			// refresh swap), not the watchdog's own start, so a freshly rotated
			// tunnel isn't condemned for the previous one's silence.
			startedAt := m.tunnelSince
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
				// Prefer a graceful make-before-break refresh over a hard teardown:
				// build+validate a new tunnel and hot-swap onto it so existing
				// connections aren't dropped. Fall back to a full reconnect only if
				// the refresh itself fails (e.g. can't build a live tunnel at all).
				log.Printf("tunnel stall detected (%s); refreshing", reason)
				if err := m.refreshTunnel(ctx); err != nil {
					log.Printf("stall refresh failed (%v); hard reconnect", err)
					go m.reconnect()
					return
				}
				// keep watching on the same loop; the swapped tunnel reset tunnelSince.
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

	// Retry transient failures: the control API often hiccups (EOF, timeout)
	// exactly when the data path is churning, and giving up on the first
	// failure drops the proxy listener — a total outage until the user
	// manually reconnects. Only a logged-out session is fatal.
	err := retryReconnect(context.Background(), reconnectAttempts, reconnectRetryDelay,
		func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return m.connectReal(ctx, "")
		},
		corplink.IsLoggedOut,
	)
	if err != nil {
		log.Printf("wireguard reconnect failed: %v", err)
		m.setState(StateLoggedIn, "reconnect failed: "+err.Error())
		m.teardown()
	}
}

const (
	reconnectAttempts   = 5
	reconnectRetryDelay = 5 * time.Second
)

// retryReconnect runs connect up to attempts times, sleeping delay between
// failures, stopping early on success, context cancellation, or a fatal error.
func retryReconnect(ctx context.Context, attempts int, delay time.Duration, connect func() error, fatal func(error) bool) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(delay):
			}
		}
		lastErr = connect()
		if lastErr == nil {
			return nil
		}
		if fatal(lastErr) {
			return lastErr
		}
		log.Printf("reconnect attempt %d/%d failed: %v", i+1, attempts, lastErr)
	}
	return lastErr
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
