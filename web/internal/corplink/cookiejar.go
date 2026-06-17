package corplink

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// storedCookie is the persisted form of a cookie.
type storedCookie struct {
	Name    string    `json:"name"`
	Value   string    `json:"value"`
	Host    string    `json:"host"`
	Path    string    `json:"path"`
	Expires time.Time `json:"expires,omitempty"`
}

// persistentJar is an http.CookieJar that persists to a JSON file and supports
// copying a host's cookies to another host (used to carry the authenticated
// session to a VPN node's IP when probing/connecting).
type persistentJar struct {
	mu   sync.Mutex
	path string
	// host -> name -> cookie
	store map[string]map[string]storedCookie
}

var _ http.CookieJar = (*persistentJar)(nil)

func newPersistentJar(path string) *persistentJar {
	j := &persistentJar{path: path, store: map[string]map[string]storedCookie{}}
	j.load()
	return j
}

func (j *persistentJar) load() {
	data, err := os.ReadFile(j.path)
	if err != nil {
		return
	}
	var flat []storedCookie
	if err := json.Unmarshal(data, &flat); err != nil {
		return
	}
	for _, c := range flat {
		j.setLocked(c)
	}
}

func (j *persistentJar) persistLocked() {
	var flat []storedCookie
	for _, byName := range j.store {
		for _, c := range byName {
			flat = append(flat, c)
		}
	}
	data, err := json.MarshalIndent(flat, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(j.path, data, 0o600)
}

func (j *persistentJar) setLocked(c storedCookie) {
	if c.Path == "" {
		c.Path = "/"
	}
	if j.store[c.Host] == nil {
		j.store[c.Host] = map[string]storedCookie{}
	}
	j.store[c.Host][c.Name] = c
}

// SetCookies implements http.CookieJar.
func (j *persistentJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		j.setLocked(storedCookie{
			Name:    c.Name,
			Value:   c.Value,
			Host:    u.Hostname(),
			Path:    c.Path,
			Expires: c.Expires,
		})
	}
	j.persistLocked()
}

// Cookies implements http.CookieJar.
func (j *persistentJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	var out []*http.Cookie
	for _, c := range j.store[u.Hostname()] {
		if !c.Expires.IsZero() && c.Expires.Before(now) {
			continue
		}
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path})
	}
	return out
}

// set inserts or replaces a single cookie for a host.
func (j *persistentJar) set(host, name, value string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.setLocked(storedCookie{Name: name, Value: value, Host: host, Path: "/"})
	j.persistLocked()
}

// get returns the value of a cookie for a host (path is ignored, all corplink
// cookies are path "/"), reporting whether it was found.
func (j *persistentJar) get(host, name string) (string, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if byName, ok := j.store[host]; ok {
		if c, ok := byName[name]; ok {
			return c.Value, true
		}
	}
	return "", false
}

// copyHost copies all of src's cookies onto dst, so the authenticated session
// follows when the request host is rewritten to a node IP.
func (j *persistentJar) copyHost(src, dst string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range j.store[src] {
		c.Host = dst
		j.setLocked(c)
	}
	j.persistLocked()
}

// clear removes all stored cookies (used on logout).
func (j *persistentJar) clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store = map[string]map[string]storedCookie{}
	j.persistLocked()
}
