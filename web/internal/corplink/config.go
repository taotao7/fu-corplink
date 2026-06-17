package corplink

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Route modes select which route list returned by the server is applied to the
// tunnel. "full" mimics a global tunnel (server-supplied full routes), "split"
// only routes the intranet ranges the server advertises.
const (
	RouteModeFull  = "full"
	RouteModeSplit = "split"
)

// Login platforms understood by the upstream corplink/feilian backend.
const (
	PlatformLDAP        = "ldap"
	PlatformCorplink    = "feilian"
	PlatformCorplinkV1  = "feilian_v1"
	PlatformOIDC        = "OIDC"
	PlatformLark        = "lark"
)

// VPN node selection strategies.
const (
	StrategyDefault = "default"
	StrategyLatency = "latency"
)

const (
	defaultDeviceName  = "DollarOS"
	defaultSocksListen = "0.0.0.0:8989"
	cookieFileSuffix   = "cookies.json"
)

// Config is the on-disk configuration. It is shared between the corplink client
// (which uses the upstream-facing fields) and the web control panel (which
// exposes the operator-facing proxy/admin fields). It is persisted as pretty
// JSON next to the binary's working directory.
type Config struct {
	// identity / upstream
	CompanyName string `json:"company_name"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Code        string `json:"code,omitempty"` // base32 TOTP secret
	Server      string `json:"server,omitempty"`

	// device
	DeviceName     string `json:"device_name,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	AndroidRelease string `json:"android_release,omitempty"`
	SecurityPatch  string `json:"security_patch,omitempty"`

	// wireguard keypair (base64, standard encoding)
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`

	// node selection
	VPNServerID       int    `json:"vpn_server_id"`
	VPNServerName     string `json:"vpn_server_name,omitempty"`
	VPNSelectStrategy string `json:"vpn_select_strategy,omitempty"`
	RouteMode         string `json:"route_mode,omitempty"`
	ForceProtocol     string `json:"force_protocol,omitempty"`

	// proxy (data plane) — the mixed HTTP/SOCKS5 listener
	SocksListen      string `json:"socks_listen,omitempty"`
	SocksUDPEnabled  bool   `json:"socks_udp_enabled,omitempty"`
	ProxyAuthEnabled bool   `json:"proxy_auth_enabled,omitempty"`
	ProxyUsername    string `json:"proxy_username,omitempty"`
	ProxyPassword    string `json:"proxy_password,omitempty"`

	// admin (control plane auth gate)
	AdminAuthEnabled bool   `json:"admin_auth_enabled,omitempty"`
	AdminUsername    string `json:"admin_username,omitempty"`
	AdminPassword    string `json:"admin_password,omitempty"`

	// misc
	StrictMode bool `json:"strict_mode,omitempty"`

	// runtime-only, never serialized
	path string
	mu   sync.Mutex
}

// LoadConfig reads the config from file, applying defaults and persisting back
// any generated fields (device id, wireguard keypair, default proxy listen).
// A missing or empty file is treated as a fresh config.
func LoadConfig(path string) (*Config, error) {
	c := &Config{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil && len(strings.TrimSpace(string(data))) > 0:
		if err := json.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		c.path = path
	case err != nil && !os.IsNotExist(err):
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	changed, err := c.ensureDefaults()
	if err != nil {
		return nil, err
	}
	if changed {
		if err := c.Save(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// ensureDefaults fills in any missing generated fields and reports whether the
// config was modified (and therefore needs persisting).
func (c *Config) ensureDefaults() (bool, error) {
	changed := false
	if c.DeviceName == "" {
		c.DeviceName = defaultDeviceName
		changed = true
	}
	if c.DeviceID == "" {
		c.DeviceID = fmt.Sprintf("%x", md5.Sum([]byte(c.DeviceName)))
		changed = true
	}
	c.initAndroidDevice(&changed)
	if c.SocksListen == "" {
		c.SocksListen = defaultSocksListen
		changed = true
	}
	if c.RouteMode == "" {
		c.RouteMode = RouteModeFull
		changed = true
	}
	if c.VPNSelectStrategy == "" {
		c.VPNSelectStrategy = StrategyDefault
		changed = true
	}
	switch {
	case c.PrivateKey != "" && c.PublicKey == "":
		pub, err := PublicKeyFromPrivate(c.PrivateKey)
		if err != nil {
			return changed, err
		}
		c.PublicKey = pub
		changed = true
	case c.PrivateKey == "":
		pub, priv, err := GenerateKeypair()
		if err != nil {
			return changed, err
		}
		c.PublicKey, c.PrivateKey = pub, priv
		changed = true
	}
	return changed, nil
}

// initAndroidDevice picks a plausible Android model/patch level the first time,
// used by the device-report body sent to the server.
func (c *Config) initAndroidDevice(changed *bool) {
	if c.AndroidRelease == "" {
		c.AndroidRelease = androidModels[0].release
		*changed = true
	}
	if c.SecurityPatch == "" {
		c.SecurityPatch = androidPatchDates[0]
		*changed = true
	}
}

// Validate checks the minimal required fields for the client to operate.
func (c *Config) Validate() error {
	if c.PrivateKey == "" || c.PublicKey == "" {
		return fmt.Errorf("wireguard keypair missing")
	}
	return nil
}

// Save persists the config atomically as pretty JSON.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == "" {
		return fmt.Errorf("config file path missing")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize config: %w", err)
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", tmp, err)
	}
	return os.Rename(tmp, c.path)
}

// Path returns the config file path.
func (c *Config) Path() string { return c.path }

// CookieFile returns the sibling cookie jar path used to persist the session.
func (c *Config) CookieFile() string {
	dir := filepath.Dir(c.path)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "corplink_"+cookieFileSuffix)
}

// RouteModeOrDefault returns the configured route mode or the default.
func (c *Config) RouteModeOrDefault() string {
	if c.RouteMode == RouteModeSplit {
		return RouteModeSplit
	}
	return RouteModeFull
}

// deviceReportBody returns the device fingerprint fields reported to the server.
func (c *Config) deviceReportBody() map[string]any {
	return map[string]any{
		"device_id":       c.DeviceID,
		"device_name":     c.DeviceName,
		"android_release": c.AndroidRelease,
		"security_patch":  c.SecurityPatch,
	}
}
