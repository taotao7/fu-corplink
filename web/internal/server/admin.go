package server

import (
	"net/http"
	"time"
)

const adminCookieName = "corplink_admin"

// requireAdmin wraps a handler with the admin auth gate. When admin auth is
// disabled it is a pass-through; otherwise a valid session cookie is required.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.mgr.Admin().Enabled() {
			next(w, r)
			return
		}
		token := ""
		if c, err := r.Cookie(adminCookieName); err == nil {
			token = c.Value
		}
		if !s.mgr.Admin().CheckSession(token) {
			writeErr(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAdminAuth(w http.ResponseWriter, r *http.Request) {
	enabled := s.mgr.Admin().Enabled()
	authenticated := !enabled
	if enabled {
		if c, err := r.Cookie(adminCookieName); err == nil {
			authenticated = s.mgr.Admin().CheckSession(c.Value)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       enabled,
		"authenticated": authenticated,
	})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if !s.mgr.Admin().Enabled() {
		writeOK(w)
		return
	}
	body, err := decodeBody[struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}](r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	token, ok := s.mgr.Admin().Login(clientIP(r), body.Username, body.Password)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(12 * time.Hour),
	})
	writeOK(w)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(adminCookieName); err == nil {
		s.mgr.Admin().Logout(c.Value)
	}
	clearSessionCookie(w)
	writeOK(w)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}
