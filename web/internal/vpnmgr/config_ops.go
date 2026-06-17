package vpnmgr

import (
	"context"
	"fmt"
	"strings"

	"corplink-web/internal/corplink"
)

// CompanyInfo is returned to the UI after resolving a company code.
type CompanyInfo struct {
	CompanyName string `json:"company_name"`
	ZhName      string `json:"zh_name"`
	EnName      string `json:"en_name"`
	Server      string `json:"server"`
}

// SetCompany resolves a company code to its server and persists it, seeding the
// client for subsequent login calls.
func (m *Manager) SetCompany(ctx context.Context, code string) (*CompanyInfo, error) {
	info, err := corplink.GetCompany(ctx, code)
	if err != nil {
		return nil, err
	}
	server := info.Domain
	if server == "" {
		return nil, fmt.Errorf("company %q has no server domain", code)
	}
	m.mu.Lock()
	m.conf.CompanyName = code
	m.client.SetServer(server)
	m.mu.Unlock()
	if err := m.conf.Save(); err != nil {
		return nil, err
	}
	return &CompanyInfo{
		CompanyName: code,
		ZhName:      info.ZhName,
		EnName:      info.EnName,
		Server:      server,
	}, nil
}

// ConfigView is the operator-editable subset of config exposed to the UI.
type ConfigView struct {
	SocksListen       string `json:"socks_listen"`
	VPNServerID       int    `json:"vpn_server_id"`
	VPNSelectStrategy string `json:"vpn_select_strategy"`
	RouteMode         string `json:"route_mode"`
	ForceProtocol     string `json:"force_protocol"`
	CompanyName       string `json:"company_name"`
	Username          string `json:"username"`
}

// ConfigView returns the current editable config.
func (m *Manager) ConfigView() ConfigView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ConfigView{
		SocksListen:       m.conf.SocksListen,
		VPNServerID:       m.conf.VPNServerID,
		VPNSelectStrategy: m.conf.VPNSelectStrategy,
		RouteMode:         m.conf.RouteModeOrDefault(),
		ForceProtocol:     m.conf.ForceProtocol,
		CompanyName:       m.conf.CompanyName,
		Username:          m.conf.Username,
	}
}

// ConfigUpdate carries optional config fields to update (nil = leave unchanged).
type ConfigUpdate struct {
	SocksListen       *string `json:"socks_listen"`
	VPNServerID       *int    `json:"vpn_server_id"`
	VPNSelectStrategy *string `json:"vpn_select_strategy"`
	RouteMode         *string `json:"route_mode"`
	ForceProtocol     *string `json:"force_protocol"`
}

// UpdateConfig applies a partial config update and persists it. Changes to the
// proxy listen address take effect on the next connect.
func (m *Manager) UpdateConfig(u ConfigUpdate) error {
	m.mu.Lock()
	if u.SocksListen != nil && *u.SocksListen != "" {
		m.conf.SocksListen = *u.SocksListen
	}
	if u.VPNServerID != nil {
		m.conf.VPNServerID = *u.VPNServerID
	}
	if u.VPNSelectStrategy != nil {
		switch *u.VPNSelectStrategy {
		case corplink.StrategyDefault, corplink.StrategyLatency:
			m.conf.VPNSelectStrategy = *u.VPNSelectStrategy
		}
	}
	if u.RouteMode != nil {
		switch *u.RouteMode {
		case corplink.RouteModeFull, corplink.RouteModeSplit:
			m.conf.RouteMode = *u.RouteMode
		}
	}
	if u.ForceProtocol != nil {
		forceProtocol := strings.ToLower(strings.TrimSpace(*u.ForceProtocol))
		switch forceProtocol {
		case "", "udp", "tcp":
			m.conf.ForceProtocol = forceProtocol
		}
	}
	m.mu.Unlock()
	return m.conf.Save()
}
