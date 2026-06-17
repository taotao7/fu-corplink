package corplink

import "encoding/json"

// resp is the standard response envelope used by all corplink endpoints.
type resp[T any] struct {
	Code    int     `json:"code"`
	Message string  `json:"message,omitempty"`
	Data    *T      `json:"data,omitempty"`
	Action  string  `json:"action,omitempty"`
}

// rawResp keeps data as raw JSON so the envelope (code/message) can be inspected
// before attempting to decode data into a concrete type. The upstream server
// returns a non-zero code with a mismatched data shape on expired sessions, so
// data is only decoded once code == 0.
type rawResp struct {
	Code    int             `json:"code"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Action  string          `json:"action,omitempty"`
}

// respCompany is returned by the company lookup endpoint.
type respCompany struct {
	Name             string `json:"name"`
	ZhName           string `json:"zh_name"`
	EnName           string `json:"en_name"`
	Domain           string `json:"domain"`
	EnableSelfSigned bool   `json:"enable_self_signed"`
	SelfSignedCert   string `json:"self_signed_cert"`
	EnablePublicKey  bool   `json:"enable_public_key"`
	PublicKey        string `json:"public_key"`
}

// respLoginMethod lists the enabled login methods, in server-preferred order.
type respLoginMethod struct {
	LoginEnableLDAP bool     `json:"login_enable_ldap"`
	LoginEnable     bool     `json:"login_enable"`
	LoginOrders     []string `json:"login_orders"`
}

// respTpsLoginMethod describes a third-party (SSO) login option.
type respTpsLoginMethod struct {
	Alias    string `json:"alias"`
	LoginURL string `json:"login_url"`
	Token    string `json:"token"`
}

// respCorplinkLoginMethod is the corplink/feilian lookup response.
type respCorplinkLoginMethod struct {
	MFA  bool     `json:"mfa"`
	Auth []string `json:"auth"`
}

// respLogin is the common login response carrying an optional redirect url.
type respLogin struct {
	URL string `json:"url"`
}

// respLoginV1 is the v1 (AES password) login response.
type respLoginV1 struct {
	Result string `json:"result"`
}

// respOtp carries the otpauth uri (containing the TOTP secret) and a code.
type respOtp struct {
	URL  string `json:"url"`
	Code string `json:"code"`
}

// VPNInfo describes a VPN node from /api/vpn/list.
type VPNInfo struct {
	APIPort      uint16 `json:"api_port"`
	VPNPort      uint16 `json:"vpn_port"`
	IP           string `json:"ip"`
	ProtocolMode int    `json:"protocol_mode"` // 1 tcp, 2 udp
	Name         string `json:"name"`
	EnName       string `json:"en_name"`
	Icon         string `json:"icon"`
	ID           int    `json:"id"`
	Timeout      int    `json:"timeout"`

	// LatencyMS is filled in by the client after probing; -1 means timeout.
	LatencyMS int64 `json:"latency_ms"`
}

// respWgExtraInfo is the routing/dns settings block of the connect response.
type respWgExtraInfo struct {
	VPNMTU            uint32   `json:"vpn_mtu"`
	VPNDNS            string   `json:"vpn_dns"`
	VPNDNSBackup      string   `json:"vpn_dns_backup"`
	VPNDNSDomainSplit []string `json:"vpn_dns_domain_split"`
	VPNRouteFull      []string `json:"vpn_route_full"`
	VPNRouteSplit     []string `json:"vpn_route_split"`
	V6RouteFull       []string `json:"v6_route_full"`
	V6RouteSplit      []string `json:"v6_route_split"`
}

// respWgInfo is the WireGuard handshake info from /vpn/conn.
type respWgInfo struct {
	IP        string          `json:"ip"`
	IPv6      string          `json:"ipv6"`
	IPMask    string          `json:"ip_mask"`
	PublicKey string          `json:"public_key"`
	Setting   respWgExtraInfo `json:"setting"`
	Mode      uint32          `json:"mode"`
}
