package guard

import (
	"bufio"
	"bytes"
	stdctx "context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lockhinator/kubectl-guard/config"
)

// shortNameCacheTTL is how long a discovered api-resources short-name map is
// trusted before it is refreshed. CRD short names change rarely, so a modest TTL
// keeps the guard off the (latency-heavy) api-resources call on the common path
// while still picking up newly-installed CRDs within the window.
const shortNameCacheTTL = 10 * time.Minute

const apiResourcesCacheFile = ".kubectl-guard-api-resources.cache"

// shortNameCache is the on-disk cache of discovered short names, keyed to the
// cluster it was gathered from so a context switch does not reuse another
// cluster's map.
type shortNameCache struct {
	Time       int64             `json:"time"`        // unix seconds when gathered
	Key        string            `json:"key"`         // hash of (kubeconfig, context)
	ShortNames map[string]string `json:"short_names"` // short name -> canonical resource
}

// DiscoverShortNames returns a map of discovered CRD short names to their
// canonical resource form (e.g. "ss" -> "secretstore"), for the cluster the
// command targets (--kubeconfig/--context, else ambient). It is BEST-EFFORT and
// fail-safe: any error (discovery disabled, kubectl missing, offline, RBAC
// denied, unparseable output, unreadable cache) returns nil, leaving matching on
// the built-in short names. It NEVER blocks the guard and NEVER removes a
// mapping, so discovery can only ever add protection, not weaken it.
//
// A fresh cache (within shortNameCacheTTL and matching the cluster key) is used
// without shelling out; otherwise `kubectl api-resources` runs once and the
// result is cached.
func DiscoverShortNames(cfg *config.Config, args []string) map[string]string {
	if cfg == nil || !cfg.ShouldDiscoverShortNames() {
		return nil
	}

	p := ParseArgs(args)
	key := cacheKey(p.Kubeconfig, p.Context)

	if m, ok := readShortNameCache(key, timeNow()); ok {
		return m
	}

	m, err := runAPIResources(p.Kubeconfig, p.Context)
	if err != nil {
		// Fall back to built-ins. Do not cache a failure — retry next time.
		return nil
	}
	writeShortNameCache(key, m, timeNow())
	return m
}

// timeNow is a seam so tests can control cache freshness deterministically.
var timeNow = func() int64 { return time.Now().Unix() }

func cacheKey(kubeconfig, context string) string {
	sum := sha256.Sum256([]byte(kubeconfig + "\x00" + context))
	return fmt.Sprintf("%x", sum[:8])
}

func apiResourcesCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, apiResourcesCacheFile), nil
}

// readShortNameCache returns the cached map if it exists, is unexpired, and was
// gathered for the same cluster key. Any problem returns ok=false so the caller
// falls through to a fresh discovery.
func readShortNameCache(key string, now int64) (map[string]string, bool) {
	path, err := apiResourcesCachePath()
	if err != nil {
		return nil, false
	}
	// Defense in depth: the cache only ever ADDS matches (over-blocks), so it
	// cannot open a bypass — but a group/world-writable cache is a smell (another
	// user could fill it with over-blocking noise), so ignore it and re-discover.
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o022 != 0 {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var c shortNameCache
	if json.Unmarshal(data, &c) != nil {
		return nil, false
	}
	if c.Key != key {
		return nil, false // cache is for a different cluster
	}
	if now-c.Time > int64(shortNameCacheTTL/time.Second) {
		return nil, false // expired
	}
	return c.ShortNames, true
}

// writeShortNameCache persists the map (best-effort; a write failure is ignored
// because discovery must never break a command).
func writeShortNameCache(key string, m map[string]string, now int64) {
	path, err := apiResourcesCachePath()
	if err != nil {
		return
	}
	data, err := json.Marshal(shortNameCache{Time: now, Key: key, ShortNames: m})
	if err != nil {
		return
	}
	// Atomic-ish: write to a temp file then rename, so a concurrent reader never
	// sees a half-written cache.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kubectl-guard-apires-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpName, path)
}

// apiResourcesTimeout bounds the discovery subprocess. Discovery is best-effort
// enrichment on the command's critical path, so it must never hang the guard: a
// slow apiserver, a hung kubectl, or a stalled exec-credential auth plugin gives
// up here and falls back to the built-in short names. It is a var so tests can
// shrink it.
var apiResourcesTimeout = 3 * time.Second

// runAPIResources shells out to `kubectl api-resources` for the given target and
// parses the short-name map from its output. It is bounded by apiResourcesTimeout.
func runAPIResources(kubeconfig, context string) (map[string]string, error) {
	ctx, cancel := stdctx.WithTimeout(stdctx.Background(), apiResourcesTimeout)
	defer cancel()

	base := []string{}
	if kubeconfig != "" {
		base = append(base, "--kubeconfig="+kubeconfig)
	}
	if context != "" {
		base = append(base, "--context="+context)
	}
	// --no-headers to skip the header row; --cached to reuse kubectl's own
	// discovery cache and keep this fast.
	base = append(base, "api-resources", "--no-headers", "--cached")
	cmd, err := kubectlCommandContext(ctx, base...)
	if err != nil {
		return nil, err
	}
	// The context deadline SIGKILLs the direct kubectl process, but if it (e.g. a
	// PATH shim wrapping the real binary) leaves a child holding the stdout pipe,
	// cmd.Output() would block on that pipe long after the deadline. WaitDelay
	// force-closes the pipes shortly after the process is signalled, so a lingering
	// descendant cannot hang the guard beyond the deadline. See
	// TestDiscoverShortNamesTimeout.
	cmd.WaitDelay = apiResourcesTimeout
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseAPIResources(out), nil
}

// parseAPIResources parses `kubectl api-resources --no-headers` output into a
// short-name -> canonical-resource map.
//
// The columns are: NAME  SHORTNAMES  APIVERSION  NAMESPACED  KIND. SHORTNAMES may
// be EMPTY, which makes a left-anchored field split ambiguous. The last three
// columns are always single tokens (apiversion, true/false, a Kind identifier),
// so the parse is RIGHT-anchored: name=fields[0], kind=fields[len-1],
// shortnames=fields[1:len-3] (zero or one comma-joined token). A line with fewer
// than 4 fields, or an empty short-name cell, contributes nothing.
func parseAPIResources(out []byte) map[string]string {
	m := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		kind := fields[len(fields)-1]
		canonical := config.NormalizeResource(kind)
		if canonical == "" {
			continue
		}
		// Map the plural NAME (fields[0]) to the canonical kind as well. For a CRD
		// with an IRREGULAR plural (e.g. ciliumnetworkpolicy -> ciliumnetworkpolicies),
		// NormalizeResource cannot singularize the typed plural back to the kind, so
		// without this a user protecting the CRD by kind would still leak
		// `kubectl get <plural>`. (Regular-plural CRDs already match via the "-s"
		// trim; this is redundant-but-harmless for them.) The plural is never a
		// short name, so it is added, never shadowing anything.
		if name := strings.ToLower(fields[0]); name != "" {
			m[name] = canonical
		}
		// fields[1 : len-3] is the short-names cell (empty when absent). A
		// discovered short name that collides with a built-in is harmless:
		// IsResourceProtected uses the discovered map only to ADD matches, never
		// to change the built-in normalization of a protected entry.
		for _, cell := range fields[1 : len(fields)-3] {
			for _, short := range strings.Split(cell, ",") {
				short = strings.ToLower(strings.TrimSpace(short))
				if short != "" {
					m[short] = canonical
				}
			}
		}
	}
	return m
}
