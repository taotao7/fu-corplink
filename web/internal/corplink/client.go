package corplink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errLoggedOut signals that the server reported the session as logged out and
// the caller should reset state and (optionally) retry after re-login.
type errLoggedOut struct{ msg string }

func (e *errLoggedOut) Error() string { return "operation failed because of logout: " + e.msg }

// IsLoggedOut reports whether err indicates a server-side session logout.
func IsLoggedOut(err error) bool {
	var e *errLoggedOut
	return errors.As(err, &e)
}

// Client speaks the corplink protocol for a single configured account. It is
// safe for sequential use; the owning Manager serializes access.
type Client struct {
	conf *Config
	hc   *http.Client
	jar  *persistentJar

	mu            sync.Mutex
	timeOffsetSec int    // server clock skew, from the Date header
	vpnBase       string // current VPN-node base url for data-plane calls

	probeMu sync.Mutex // serializes latency probes (shared vpnBase/cookies)
}

// NewClient builds a client from config, loading any persisted cookie jar and
// seeding the device cookies / csrf header.
func NewClient(conf *Config) (*Client, error) {
	jar := newPersistentJar(conf.CookieFile())

	c := &Client{
		conf: conf,
		jar:  jar,
		hc: &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				// the corplink gateway presents a cert signed by its own CA
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if conf.Server != "" {
		c.seedDeviceCookies()
	}
	return c, nil
}

// SetServer sets (or changes) the company server base url and seeds the device
// cookies for it.
func (c *Client) SetServer(server string) {
	c.conf.Server = server
	c.seedDeviceCookies()
}

func (c *Client) seedDeviceCookies() {
	host, err := hostOf(c.conf.Server)
	if err != nil {
		return
	}
	if c.conf.DeviceID != "" {
		c.jar.set(host, "device_id", c.conf.DeviceID)
	}
	if c.conf.DeviceName != "" {
		c.jar.set(host, "device_name", c.conf.DeviceName)
	}
}

func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("no host in url %q", rawURL)
	}
	return u.Hostname(), nil
}

// request issues an API call and decodes the standard envelope. A GET is used
// when body is nil, otherwise a JSON POST. The csrf-token header is attached
// from the session cookie when present.
func (c *Client) request(ctx context.Context, api apiName, body map[string]any, out any) (*rawResp, error) {
	base := c.conf.Server
	if api.isVPNScoped() {
		c.mu.Lock()
		base = c.vpnBase
		c.mu.Unlock()
	}
	if base == "" {
		return nil, fmt.Errorf("server url missing for %s", api)
	}
	reqURL := api.renderURL(base)

	var req *http.Request
	var err error
	if body != nil {
		buf, mErr := json.Marshal(body)
		if mErr != nil {
			return nil, fmt.Errorf("serialize body for %s: %w", api, mErr)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(buf))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	c.attachCSRF(req, base)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %w", api, err)
	}
	defer resp.Body.Close()

	c.parseTimeOffset(resp)

	if resp.StatusCode >= 400 {
		return nil, &errLoggedOut{msg: fmt.Sprintf("bad resp code: %s", resp.Status)}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response for %s: %w", api, err)
	}
	// Endpoints like /api/logout reply with a redirect / empty body.
	if len(bytes.TrimSpace(data)) == 0 {
		return &rawResp{Code: 0}, nil
	}
	var raw rawResp
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse envelope for %s: %s: %w", api, string(data), err)
	}
	if raw.Code == 0 && out != nil && len(raw.Data) > 0 {
		if err := json.Unmarshal(raw.Data, out); err != nil {
			return nil, fmt.Errorf("parse data for %s: %w", api, err)
		}
	}
	return &raw, nil
}

// attachCSRF copies the csrf-token cookie into the matching header, which the
// server validates as a double-submit token on state-changing endpoints.
func (c *Client) attachCSRF(req *http.Request, base string) {
	host, err := hostOf(base)
	if err != nil {
		return
	}
	if token, ok := c.jar.get(host, "csrf-token"); ok {
		req.Header.Set("csrf-token", token)
	}
}

// parseTimeOffset records the difference between server and local time from the
// HTTP Date header, so TOTP codes can be corrected for clock skew.
func (c *Client) parseTimeOffset(resp *http.Response) {
	dateStr := resp.Header.Get("Date")
	if dateStr == "" {
		return
	}
	serverTime, err := http.ParseTime(dateStr)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.timeOffsetSec = int(serverTime.Sub(time.Now()).Seconds())
	c.mu.Unlock()
}

// GetCompany resolves a company code to its server domain (and zh/en names).
func GetCompany(ctx context.Context, code string) (*respCompany, error) {
	hc := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	buf, _ := json.Marshal(map[string]any{"code": code})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, URLGetCompany, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	httpResp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get company: %w", err)
	}
	defer httpResp.Body.Close()
	var envelope resp[respCompany]
	if err := json.NewDecoder(httpResp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("parse company resp: %w", err)
	}
	if envelope.Code != 0 || envelope.Data == nil {
		msg := envelope.Message
		if msg == "" {
			msg = "failed to fetch company info"
		}
		return nil, errors.New(msg)
	}
	return envelope.Data, nil
}

// --- Login methods -------------------------------------------------------

// LoginMethods is the set of available login options surfaced to the UI.
type LoginMethods struct {
	LoginOrders     []string         `json:"login_orders"`
	LoginEnableLDAP bool             `json:"login_enable_ldap"`
	LoginEnable     bool             `json:"login_enable"`
	TPS             []TpsLoginOption `json:"tps"`
}

// TpsLoginOption is a third-party SSO login option.
type TpsLoginOption struct {
	Alias    string `json:"alias"`
	LoginURL string `json:"login_url"`
	Token    string `json:"token"`
}

// GetLoginMethods fetches the enabled login methods plus any SSO options.
func (c *Client) GetLoginMethods(ctx context.Context) (*LoginMethods, error) {
	var lm respLoginMethod
	if _, err := c.request(ctx, apiLoginMethod, nil, &lm); err != nil {
		return nil, err
	}
	out := &LoginMethods{
		LoginOrders:     lm.LoginOrders,
		LoginEnableLDAP: lm.LoginEnableLDAP,
		LoginEnable:     lm.LoginEnable,
	}
	// SSO options are best-effort; ignore failures.
	var tps []respTpsLoginMethod
	if _, err := c.request(ctx, apiTpsLoginMethod, nil, &tps); err == nil {
		for _, t := range tps {
			out.TPS = append(out.TPS, TpsLoginOption{Alias: t.Alias, LoginURL: t.LoginURL, Token: t.Token})
		}
	}
	return out, nil
}

// LoginWithPassword performs a password login for the corplink or ldap
// platform. For corplink the password is sha256-hashed (unless already a 64-char
// hash); for ldap it is sent as-is with platform=ldap.
func (c *Client) LoginWithPassword(ctx context.Context, username, password, platform string) error {
	if platform == "" {
		platform = PlatformCorplink
	}
	c.conf.Username = username
	c.conf.Platform = platform

	if platform == PlatformCorplinkV1 {
		return c.loginV1(ctx, username, password)
	}

	body := map[string]any{"user_name": username}
	switch platform {
	case PlatformLDAP:
		body["platform"] = PlatformLDAP
		body["password"] = password
	case PlatformCorplink:
		if len(password) != 64 {
			password = sha256Hex(password)
		}
		body["password"] = password
	default:
		return fmt.Errorf("invalid platform %q", platform)
	}

	var login respLogin
	raw, err := c.request(ctx, apiLoginPassword, body, &login)
	if err != nil {
		return err
	}
	if raw.Code != 0 {
		return errors.New(orDefault(raw.Message, "login with password failed"))
	}
	return c.finalizeLogin(ctx)
}

// loginV1 performs the newer feilian v1 login with an AES-encrypted password.
func (c *Client) loginV1(ctx context.Context, username, password string) error {
	if password == "" {
		return fmt.Errorf("platform feilian_v1 requires a password")
	}
	enc, err := feilianV1EncryptPassword(password)
	if err != nil {
		return err
	}
	body := map[string]any{
		"login_scene":  PlatformCorplink,
		"account_type": "userid",
		"account":      username,
		"password":     enc,
	}
	var v1 respLoginV1
	raw, err := c.request(ctx, apiLoginPasswordV1, body, &v1)
	if err != nil {
		return err
	}
	if raw.Code != 0 {
		return errors.New(orDefault(raw.Message, "v1 login failed"))
	}
	if v1.Result != "success" {
		return fmt.Errorf("v1 login returned unexpected result: %s", v1.Result)
	}
	return c.finalizeLogin(ctx)
}

// RequestEmailCode asks the server to send a login code to the user's email.
func (c *Client) RequestEmailCode(ctx context.Context, username string) error {
	c.conf.Username = username
	body := map[string]any{
		"forget_password": false,
		"code_type":       "email",
		"user_name":       username,
	}
	_, err := c.request(ctx, apiRequestEmailCode, body, nil)
	return err
}

// LoginWithEmail verifies an emailed login code.
func (c *Client) LoginWithEmail(ctx context.Context, username, code string) error {
	c.conf.Username = username
	body := map[string]any{
		"forget_password": false,
		"code_type":       "email",
		"code":            code,
	}
	var login respLogin
	raw, err := c.request(ctx, apiLoginEmail, body, &login)
	if err != nil {
		return err
	}
	if raw.Code != 0 {
		return fmt.Errorf("failed to login with email code: %s", orDefault(raw.Message, "unknown error"))
	}
	return c.finalizeLogin(ctx)
}

// CheckTpsToken polls a third-party login token, returning the redirect url
// once the SSO flow is confirmed.
func (c *Client) CheckTpsToken(ctx context.Context, token string) (string, error) {
	body := map[string]any{"token": token}
	var login respLogin
	raw, err := c.request(ctx, apiTpsTokenCheck, body, &login)
	if err != nil {
		return "", err
	}
	if raw.Code != 0 {
		return "", errors.New(orDefault(raw.Message, "tps token check failed"))
	}
	return login.URL, nil
}

// finalizeLogin marks the session as logged in and best-effort fetches the TOTP
// secret so 2FA codes can be generated locally on connect.
func (c *Client) finalizeLogin(ctx context.Context) error {
	if uri, err := c.requestOtpURI(ctx); err == nil && uri != "" {
		if secret := otpSecretFromURI(uri); secret != "" {
			c.conf.Code = secret
		}
	}
	return c.conf.Save()
}

// requestOtpURI fetches the otpauth uri carrying the TOTP secret.
func (c *Client) requestOtpURI(ctx context.Context) (string, error) {
	var otp respOtp
	raw, err := c.request(ctx, apiOtp, map[string]any{}, &otp)
	if err != nil {
		return "", err
	}
	if raw.Code != 0 {
		return "", errors.New(orDefault(raw.Message, "request otp failed"))
	}
	return otp.URL, nil
}

func otpSecretFromURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return u.Query().Get("secret")
}

// genOTP generates the current 6-digit TOTP code, corrected for server clock
// skew. Returns an empty string when no secret is configured.
func (c *Client) genOTP() (string, error) {
	if c.conf.Code == "" {
		return "", nil
	}
	key, err := b32Decode(strings.ToUpper(c.conf.Code))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	c.mu.Lock()
	offset := c.timeOffsetSec / totpTimeStep
	c.mu.Unlock()
	slot := totpOffset(key, offset)
	return fmt.Sprintf("%06d", slot.code), nil
}

// HasOTPSecret reports whether a TOTP secret is configured (so the UI knows
// whether it must prompt for a 2FA code on connect).
func (c *Client) HasOTPSecret() bool { return c.conf.Code != "" }

// --- VPN nodes -----------------------------------------------------------

// ListVPN fetches the available VPN nodes, filtered to supported protocols.
func (c *Client) ListVPN(ctx context.Context) ([]VPNInfo, error) {
	var vpns []VPNInfo
	raw, err := c.request(ctx, apiListVPN, nil, &vpns)
	if err != nil {
		return nil, err
	}
	switch raw.Code {
	case 0:
		filtered := vpns[:0]
		for _, v := range vpns {
			if v.ProtocolMode == 1 || v.ProtocolMode == 2 {
				v.LatencyMS = 0
				filtered = append(filtered, v)
			}
		}
		return filtered, nil
	case 101:
		return nil, c.loggedOut(orDefault(raw.Message, "logout required"))
	default:
		return nil, fmt.Errorf("list vpn failed with code %d: %s", raw.Code, raw.Message)
	}
}

// pingNode probes a node's api port (carrying the session cookie) and returns
// the round-trip latency in ms, or an error on timeout/failure.
func (c *Client) pingNode(ctx context.Context, ip string, apiPort uint16) (int64, error) {
	if err := c.setVPNBase(ip, apiPort); err != nil {
		return 0, err
	}
	start := time.Now()
	raw, err := c.request(ctx, apiPingVPN, nil, nil)
	if err != nil {
		return 0, err
	}
	if raw.Code != 0 {
		return 0, fmt.Errorf("ping vpn failed with code %d: %s", raw.Code, raw.Message)
	}
	return time.Since(start).Milliseconds(), nil
}

// ProbeLatencies pings every node and fills in LatencyMS (-1 on timeout). Nodes
// are probed concurrently with a bounded worker pool.
func (c *Client) ProbeLatencies(ctx context.Context, vpns []VPNInfo) []VPNInfo {
	type result struct {
		idx     int
		latency int64
	}
	results := make(chan result, len(vpns))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range vpns {
		wg.Add(1)
		go func(idx int, v VPNInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// Probing mutates the shared vpnBase/cookies, so serialize via the
			// client mutex per probe.
			latency, err := c.pingNodeLocked(ctx, v.IP, v.APIPort)
			if err != nil {
				latency = -1
			}
			results <- result{idx: idx, latency: latency}
		}(i, vpns[i])
	}
	go func() { wg.Wait(); close(results) }()
	for r := range results {
		vpns[r.idx].LatencyMS = r.latency
	}
	return vpns
}

// pingNodeLocked serializes a probe so concurrent calls don't race on the
// shared vpnBase / cookie jar.
func (c *Client) pingNodeLocked(ctx context.Context, ip string, apiPort uint16) (int64, error) {
	c.probeMu.Lock()
	defer c.probeMu.Unlock()
	return c.pingNode(ctx, ip, apiPort)
}

// setVPNBase rewrites the data-plane base url to a node IP and copies the
// authenticated session cookies from the server host to that IP.
func (c *Client) setVPNBase(ip string, apiPort uint16) error {
	u, err := url.Parse(c.conf.Server)
	if err != nil {
		return fmt.Errorf("invalid server url: %w", err)
	}
	srcHost := u.Hostname()
	u.Host = net.JoinHostPort(ip, strconv.Itoa(int(apiPort)))
	c.jar.copyHost(srcHost, ip)
	c.mu.Lock()
	c.vpnBase = strings.TrimRight(u.String(), "/")
	c.mu.Unlock()
	return nil
}

// FetchPeerInfo performs the WireGuard handshake exchange with a node, sending
// our public key plus a generated/explicit OTP. otpOverride, when non-empty,
// is used instead of the locally generated code.
func (c *Client) FetchPeerInfo(ctx context.Context, otpOverride string) (*respWgInfo, error) {
	otp := otpOverride
	if otp == "" {
		var err error
		if otp, err = c.genOTP(); err != nil {
			return nil, err
		}
	}
	body := map[string]any{
		"public_key": c.conf.PublicKey,
		"otp":        otp,
	}
	var info respWgInfo
	raw, err := c.request(ctx, apiConnectVPN, body, &info)
	if err != nil {
		return nil, err
	}
	switch raw.Code {
	case 0:
		return &info, nil
	case 101:
		return nil, c.loggedOut(orDefault(raw.Message, "logout required"))
	default:
		return nil, fmt.Errorf("fetch peer info failed with code %d: %s", raw.Code, raw.Message)
	}
}

// activateNode prepares the data-plane base for the chosen node (used before
// FetchPeerInfo when connecting to a pinned node without a latency probe).
func (c *Client) activateNode(v VPNInfo) error {
	return c.setVPNBase(v.IP, v.APIPort)
}

// ReportDevice sends a connect (type 100) or disconnect (type 101) status
// report to the node for the given tunnel address / mode.
func (c *Client) ReportDevice(ctx context.Context, address, mode string, disconnect bool) error {
	reportType := "100"
	api := apiKeepAliveVPN
	if disconnect {
		reportType = "101"
		api = apiDisconnectVPN
	}
	body := map[string]any{
		"ip":         address,
		"public_key": c.conf.PublicKey,
		"mode":       mode,
		"type":       reportType,
	}
	raw, err := c.request(ctx, api, body, nil)
	if err != nil {
		return err
	}
	if raw.Code != 0 {
		return fmt.Errorf("report device failed with code %d: %s", raw.Code, raw.Message)
	}
	return nil
}

// Logout signs out the current terminal (best-effort), attaching the csrf
// header explicitly since the endpoint validates it.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.request(ctx, apiLogout, nil, nil)
	c.jar.clear()
	return err
}

func (c *Client) loggedOut(msg string) error { return &errLoggedOut{msg: msg} }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
