package vpnmgr

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"corplink-web/internal/corplink"
)

const (
	adminSessionTTL    = 12 * time.Hour
	adminMaxSessions   = 64
	adminMaxFailures   = 16
	adminFailureWindow = 15 * time.Minute
	adminLockThreshold = 5
)

// adminAuth is an in-memory session/failure tracker gating the control panel
// when admin_auth_enabled is set. Sessions are opaque random tokens stored in a
// cookie; failed logins are rate-limited per client.
type adminAuth struct {
	conf *corplink.Config

	mu       sync.Mutex
	sessions map[string]time.Time   // token -> expiry
	failures map[string][]time.Time // client -> failure timestamps
}

func newAdminAuth(conf *corplink.Config) *adminAuth {
	return &adminAuth{
		conf:     conf,
		sessions: map[string]time.Time{},
		failures: map[string][]time.Time{},
	}
}

// Enabled reports whether admin auth is required.
func (a *adminAuth) Enabled() bool { return a.conf.AdminAuthEnabled }

// CheckSession reports whether token maps to a live session.
func (a *adminAuth) CheckSession(token string) bool {
	if !a.Enabled() {
		return true
	}
	if token == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.sessions, token)
		return false
	}
	return true
}

// Login validates credentials and returns a new session token on success.
func (a *adminAuth) Login(client, username, password string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lockedLocked(client) {
		return "", false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.conf.AdminUsername)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.conf.AdminPassword)) == 1
	if !userOK || !passOK {
		a.recordFailureLocked(client)
		return "", false
	}
	a.clearFailureLocked(client)
	token := newSessionID()
	a.ensureSessionCapacityLocked()
	a.sessions[token] = time.Now().Add(adminSessionTTL)
	return token, true
}

// Logout clears a session token.
func (a *adminAuth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

func (a *adminAuth) lockedLocked(client string) bool {
	a.cleanupFailuresLocked(client)
	return len(a.failures[client]) >= adminLockThreshold
}

func (a *adminAuth) recordFailureLocked(client string) {
	a.cleanupFailuresLocked(client)
	a.failures[client] = append(a.failures[client], time.Now())
	a.ensureFailureCapacityLocked()
}

func (a *adminAuth) clearFailureLocked(client string) { delete(a.failures, client) }

func (a *adminAuth) cleanupFailuresLocked(client string) {
	cutoff := time.Now().Add(-adminFailureWindow)
	kept := a.failures[client][:0]
	for _, t := range a.failures[client] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(a.failures, client)
	} else {
		a.failures[client] = kept
	}
}

func (a *adminAuth) ensureSessionCapacityLocked() {
	if len(a.sessions) < adminMaxSessions {
		return
	}
	// drop the soonest-expiring session
	var oldestKey string
	var oldest time.Time
	for k, exp := range a.sessions {
		if oldestKey == "" || exp.Before(oldest) {
			oldestKey, oldest = k, exp
		}
	}
	delete(a.sessions, oldestKey)
}

func (a *adminAuth) ensureFailureCapacityLocked() {
	if len(a.failures) < adminMaxFailures {
		return
	}
	for k := range a.failures {
		delete(a.failures, k)
		return
	}
}

func newSessionID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Logout signs out the upstream corplink session and resets state.
func (m *Manager) Logout(ctx context.Context) error {
	m.teardown()
	err := m.client.Logout(ctx)
	m.mu.Lock()
	m.state = StateLoggedOut
	m.curID = 0
	m.curName = ""
	m.lastErr = ""
	m.mu.Unlock()
	m.conf.Code = ""
	_ = m.conf.Save()
	return err
}
