package corplink

import (
	"container/list"
	"regexp"
	"strings"
	"sync"
)

// The forward proxy keeps a small in-memory cache of *immutable* static
// assets (content-hashed filenames à la Vite/webpack). Under aggressive
// gateway session revocation a 1MB+ asset can take many resume rounds to
// fetch; serving repeat loads from cache makes page reloads independent of
// tunnel churn. Only complete, fully-relayed 200 responses are cached, and
// only for URLs whose content hash makes staleness impossible.

// assetCacheBudget bounds total cached body bytes (LRU-evicted).
const assetCacheBudget = 64 << 20 // 64 MiB

// assetCacheMaxObject bounds a single cacheable object; larger bodies are
// relayed without capture.
const assetCacheMaxObject = 8 << 20 // 8 MiB

// immutableAssetRe extracts the would-be hash segment from names like
// "index-sICwX53r.js", "main.8f4b2c1a.chunk.js", "Filter-KaMOlR-S.js",
// "inter-v13-latin-Q0plLmNv.woff2": a separator, then >=6 hash-alphabet chars
// (base64url or hex) before a static extension.
var immutableAssetRe = regexp.MustCompile(
	`[-._]([A-Za-z0-9_-]{6,})(?:\.chunk)?\.(?:js|mjs|css|woff2?|ttf|otf|eot|svg|png|jpe?g|gif|webp|avif|ico|wasm|map)$`)

// isImmutableAssetPath reports whether the URL path names a content-hashed
// static asset, i.e. the same path can never serve different bytes. The
// candidate hash must look like output of a hasher — containing a digit or
// mixed case — so plain words ("my-component.js") don't qualify.
func isImmutableAssetPath(path string) bool {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	base := path[strings.LastIndexByte(path, '/')+1:]
	m := immutableAssetRe.FindStringSubmatch(base)
	if m == nil {
		return false
	}
	seg := m[1]
	var hasDigit, hasUpper, hasLower bool
	for _, r := range seg {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		}
	}
	return hasDigit || (hasUpper && hasLower)
}

// cachedResponse is a complete, ready-to-replay response: pre-rendered header
// block (status line + headers + blank line) and the full body. close records
// whether the header advertises Connection: close (close-delimited original),
// in which case the client conn must be closed after replay too.
type cachedResponse struct {
	header string
	body   []byte
	close  bool
}

// assetCache is a byte-budgeted LRU keyed by host+path. It also keeps the
// partial prefixes of interrupted immutable-asset transfers so progress on a
// large asset accumulates across client retries instead of restarting at zero.
type assetCache struct {
	mu     sync.Mutex
	budget int64
	used   int64
	order  *list.List // front = most recent; values are *cacheEntry
	items  map[string]*list.Element

	partials map[string]partialAsset
}

// partialAsset is the replayable prefix of an interrupted transfer: the exact
// header block already promised to a client plus the body bytes relayed so far.
type partialAsset struct {
	header     string
	body       []byte
	total      int64 // -1 when close-delimited
	closeAfter bool
}

// maxPartials bounds the partial-prefix map (evict-any policy; entries are
// small in number and self-healing).
const maxPartials = 32

type cacheEntry struct {
	key  string
	resp cachedResponse
}

func newAssetCache(budget int64) *assetCache {
	return &assetCache{
		budget:   budget,
		order:    list.New(),
		items:    make(map[string]*list.Element),
		partials: make(map[string]partialAsset),
	}
}

func (c *assetCache) get(key string) (cachedResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return cachedResponse{}, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*cacheEntry).resp, true
}

func (c *assetCache) put(key string, resp cachedResponse) {
	size := int64(len(resp.body)) + int64(len(resp.header))
	if size > c.budget {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		old := el.Value.(*cacheEntry)
		c.used -= int64(len(old.resp.body)) + int64(len(old.resp.header))
		c.order.Remove(el)
		delete(c.items, key)
	}
	for c.used+size > c.budget {
		back := c.order.Back()
		if back == nil {
			break
		}
		ev := back.Value.(*cacheEntry)
		c.used -= int64(len(ev.resp.body)) + int64(len(ev.resp.header))
		c.order.Remove(back)
		delete(c.items, ev.key)
	}
	c.items[key] = c.order.PushFront(&cacheEntry{key: key, resp: resp})
	c.used += size
	delete(c.partials, key) // complete supersedes partial
}

// putPartial remembers the prefix of an interrupted transfer. Only prefixes
// longer than any existing one are kept (progress is monotonic).
func (c *assetCache) putPartial(key string, pa partialAsset) {
	if int64(len(pa.body)) > assetCacheMaxObject || len(pa.body) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, done := c.items[key]; done {
		return // complete copy already cached
	}
	if old, ok := c.partials[key]; ok && len(old.body) >= len(pa.body) {
		return
	}
	if len(c.partials) >= maxPartials {
		for k := range c.partials {
			delete(c.partials, k)
			break
		}
	}
	c.partials[key] = pa
}

// getPartial returns the stored prefix for key, if any.
func (c *assetCache) getPartial(key string) (partialAsset, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pa, ok := c.partials[key]
	return pa, ok
}
