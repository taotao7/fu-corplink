package server

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// distFS holds the compiled React frontend embedded at build time. The Vite
// build writes its output here (web/internal/server/dist) and `//go:embed`
// bakes it into the binary, so there are no external asset dependencies.
//
//go:embed all:dist
var distFS embed.FS

// spaHandler serves the embedded single-page app: real files are served
// directly, and any unknown path falls back to index.html so client-side
// routing works.
type spaHandler struct {
	root http.FileSystem
}

func newSPAHandler() (http.Handler, error) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}
	return &spaHandler{root: http.FS(sub)}, nil
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := strings.TrimPrefix(r.URL.Path, "/")
	if upath == "" {
		upath = "index.html"
	}
	if f, err := h.root.Open(upath); err == nil {
		_ = f.Close()
		http.FileServer(h.root).ServeHTTP(w, r)
		return
	}
	serveIndex(h.root, w, r)
}

func serveIndex(root http.FileSystem, w http.ResponseWriter, r *http.Request) {
	f, err := root.Open("index.html")
	if err != nil {
		http.Error(w, "frontend not built", http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, "frontend not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if rs, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, "index.html", info.ModTime(), rs)
		return
	}
	_, _ = io.Copy(w, f)
}
