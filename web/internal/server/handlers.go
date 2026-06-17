package server

import (
	"errors"
	"net/http"

	"corplink-web/internal/vpnmgr"
)

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

func (s *Server) handleCompany(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := decodeBody[struct {
		CompanyName string `json:"company_name"`
	}](r)
	if err != nil || body.CompanyName == "" {
		writeErr(w, http.StatusBadRequest, "company_name required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	info, err := s.mgr.SetCompany(ctx, body.CompanyName)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleLoginMethods(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	methods, err := s.mgr.Client().GetLoginMethods(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, methods)
}

func (s *Server) handleLoginPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := decodeBody[struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Platform string `json:"platform"`
	}](r)
	if err != nil || body.Username == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	if err := s.mgr.Client().LoginWithPassword(ctx, body.Username, body.Password, body.Platform); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.mgr.SetLoggedIn()
	writeOK(w)
}

func (s *Server) handleEmailRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := decodeBody[struct {
		Username string `json:"username"`
	}](r)
	if err != nil || body.Username == "" {
		writeErr(w, http.StatusBadRequest, "username required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	if err := s.mgr.Client().RequestEmailCode(ctx, body.Username); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w)
}

func (s *Server) handleEmailVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := decodeBody[struct {
		Username string `json:"username"`
		Code     string `json:"code"`
	}](r)
	if err != nil || body.Code == "" {
		writeErr(w, http.StatusBadRequest, "code required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	if err := s.mgr.Client().LoginWithEmail(ctx, body.Username, body.Code); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.mgr.SetLoggedIn()
	writeOK(w)
}

func (s *Server) handleTpsCheck(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeErr(w, http.StatusBadRequest, "token required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	url, err := s.mgr.Client().CheckTpsToken(ctx, token)
	if err != nil {
		// pending is not an error to the UI; report not-yet-confirmed
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "pending": true})
		return
	}
	s.mgr.SetLoggedIn()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending": false, "url": url})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, _ := decodeBody[struct {
		ServerID int    `json:"server_id"`
		OTP      string `json:"otp"`
	}](r)
	ctx, cancel := s.ctx(r)
	defer cancel()
	err := s.mgr.Connect(ctx, body.ServerID, body.OTP)
	if errors.Is(err, vpnmgr.ErrNeedOTP) {
		writeJSON(w, http.StatusOK, map[string]any{"state": s.mgr.Status().State, "need_otp": true})
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.mgr.Status().State})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	if err := s.mgr.Disconnect(ctx); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.mgr.Status().State})
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	probe := r.URL.Query().Get("probe") != "false"
	ctx, cancel := s.ctx(r)
	defer cancel()
	servers, err := s.mgr.Servers(ctx, probe)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Traffic())
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	_ = s.mgr.Logout(ctx)
	writeOK(w)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.mgr.ConfigView())
	case http.MethodPut, http.MethodPost:
		body, err := decodeBody[vpnmgr.ConfigUpdate](r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid config body")
			return
		}
		if err := s.mgr.UpdateConfig(body); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET or PUT required")
	}
}
