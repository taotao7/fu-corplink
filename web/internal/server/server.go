package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"corplink-web/internal/vpnmgr"
)

// Server is the HTTP control panel: it serves the embedded SPA and the JSON
// REST API that drives it, delegating all VPN actions to the Manager.
type Server struct {
	mgr *vpnmgr.Manager
	spa http.Handler
}

// New builds the control-panel server.
func New(mgr *vpnmgr.Manager) (*Server, error) {
	spa, err := newSPAHandler()
	if err != nil {
		return nil, err
	}
	return &Server{mgr: mgr, spa: spa}, nil
}

// Handler returns the root http.Handler (API under /api, SPA elsewhere).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	mux.Handle("/", s.spa)
	return logRequests(mux)
}

func (s *Server) routes(mux *http.ServeMux) {
	// admin auth gate wraps the state-changing/data endpoints
	guard := s.requireAdmin

	mux.HandleFunc("/api/state", guard(s.handleState))
	mux.HandleFunc("/api/company", guard(s.handleCompany))
	mux.HandleFunc("/api/login/methods", guard(s.handleLoginMethods))
	mux.HandleFunc("/api/login/password", guard(s.handleLoginPassword))
	mux.HandleFunc("/api/login/email/request", guard(s.handleEmailRequest))
	mux.HandleFunc("/api/login/email/verify", guard(s.handleEmailVerify))
	mux.HandleFunc("/api/login/tps/check", guard(s.handleTpsCheck))
	mux.HandleFunc("/api/connect", guard(s.handleConnect))
	mux.HandleFunc("/api/disconnect", guard(s.handleDisconnect))
	mux.HandleFunc("/api/servers", guard(s.handleServers))
	mux.HandleFunc("/api/traffic", guard(s.handleTraffic))
	mux.HandleFunc("/api/logout", guard(s.handleLogout))
	mux.HandleFunc("/api/config", guard(s.handleConfig))

	// admin endpoints are not behind the gate (they establish it)
	mux.HandleFunc("/api/admin/auth", s.handleAdminAuth)
	mux.HandleFunc("/api/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", s.handleAdminLogout)
}

// ctx returns a request-scoped context with a sane timeout for upstream calls.
func (s *Server) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 30*time.Second)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"ok": true}) }

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeBody[T any](r *http.Request) (T, error) {
	var v T
	if r.Body == nil {
		return v, nil
	}
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&v)
	return v, err
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// keep logging minimal; the panel is interactive
		}
		next.ServeHTTP(w, r)
	})
}
