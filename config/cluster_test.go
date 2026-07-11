package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestProtectedClusterMatches covers the identity matcher: exact server
// (normalized for case and trailing slash), a pattern against the full URL and
// against the host (with port), and non-matches.
func TestProtectedClusterMatches(t *testing.T) {
	cases := []struct {
		name   string
		pc     ProtectedCluster
		server string
		want   bool
	}{
		{"exact match", ProtectedCluster{Server: "https://prod.eks.amazonaws.com"}, "https://prod.eks.amazonaws.com", true},
		{"exact trailing slash on config", ProtectedCluster{Server: "https://prod.eks.amazonaws.com/"}, "https://prod.eks.amazonaws.com", true},
		{"exact trailing slash on server", ProtectedCluster{Server: "https://prod.eks.amazonaws.com"}, "https://prod.eks.amazonaws.com/", true},
		{"exact case-insensitive", ProtectedCluster{Server: "https://Prod.EKS.amazonaws.com"}, "https://prod.eks.amazonaws.com", true},
		{"exact non-match", ProtectedCluster{Server: "https://prod.eks.amazonaws.com"}, "https://dev.eks.amazonaws.com", false},
		{"pattern full url", ProtectedCluster{ServerPattern: "https://*.prod.example.com*"}, "https://api.prod.example.com:443", true},
		{"pattern host with port", ProtectedCluster{ServerPattern: "*.prod.example.com:443"}, "https://api.prod.example.com:443", true},
		{"pattern bare host", ProtectedCluster{ServerPattern: "*.prod.example.com"}, "https://api.prod.example.com:443", true},
		{"pattern case-insensitive host", ProtectedCluster{ServerPattern: "*.prod.example.com"}, "https://API.PROD.EXAMPLE.COM:443", true},
		{"pattern non-match", ProtectedCluster{ServerPattern: "*.prod.example.com"}, "https://api.staging.example.com", false},
		{"empty server never matches", ProtectedCluster{Server: "https://x"}, "", false},
		// Server-string evasions that reach the SAME cluster must still match
		// (regression for the security review's F1/F2).
		{"exact trailing-dot FQDN", ProtectedCluster{Server: "https://api.prod.example.com:6443"}, "https://api.prod.example.com.:6443", true},
		{"pattern trailing-dot FQDN", ProtectedCluster{ServerPattern: "*.prod.example.com"}, "https://api.prod.example.com.:6443", true},
		{"exact default port omitted on server", ProtectedCluster{Server: "https://api.prod.example.com:443"}, "https://api.prod.example.com", true},
		{"exact default port omitted on config", ProtectedCluster{Server: "https://api.prod.example.com"}, "https://api.prod.example.com:443", true},
		{"exact userinfo stripped", ProtectedCluster{Server: "https://api.prod.example.com:6443"}, "https://z@api.prod.example.com:6443", true},
		{"trailing-dot must not over-match evil suffix", ProtectedCluster{ServerPattern: "*.prod.example.com"}, "https://api.prod.example.com.evil.com", false},
		// A full-URL server_pattern written with an explicit default port must still
		// match (regression: the target canonicalizes the port away, so the pattern
		// is matched against several target forms).
		{"pattern full url explicit default port", ProtectedCluster{ServerPattern: "https://*.prod.example.com:443"}, "https://api.prod.example.com:443", true},
		{"pattern literal full url default port", ProtectedCluster{ServerPattern: "https://api.prod.example.com:443"}, "https://api.prod.example.com:443", true},
		{"pattern full url default port no over-match", ProtectedCluster{ServerPattern: "https://*.prod.example.com:443"}, "https://api.prod.example.com.evil.com:443", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.pc.matches(tc.server); got != tc.want {
				t.Errorf("matches(%q) = %v, want %v", tc.server, got, tc.want)
			}
		})
	}
}

func TestIsClusterProtected(t *testing.T) {
	c := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod.eks.amazonaws.com"},
		{ServerPattern: "*.staging.example.com"},
	}}
	if !c.IsClusterProtected("https://prod.eks.amazonaws.com") {
		t.Error("exact server should be protected")
	}
	if !c.IsClusterProtected("https://api.staging.example.com:6443") {
		t.Error("pattern host should be protected")
	}
	if c.IsClusterProtected("https://dev.example.com") {
		t.Error("unrelated server should not be protected")
	}
	if (&Config{}).IsClusterProtected("https://x") {
		t.Error("no clusters configured should never be protected")
	}
}

func TestEffectiveClusterMode(t *testing.T) {
	// Inherit the global context mode when the entry has no explicit mode.
	inheritConfirm := &Config{
		ContextMode:       ContextModeConfirm,
		ProtectedClusters: []ProtectedCluster{{Server: "https://prod"}},
	}
	if got := inheritConfirm.EffectiveClusterMode("https://prod"); got != ContextModeConfirm {
		t.Errorf("inherit(confirm) = %q, want confirm", got)
	}
	inheritBlock := &Config{
		ContextMode:       ContextModeBlock,
		ProtectedClusters: []ProtectedCluster{{Server: "https://prod"}},
	}
	if got := inheritBlock.EffectiveClusterMode("https://prod"); got != ContextModeBlock {
		t.Errorf("inherit(block) = %q, want block", got)
	}
	// Explicit per-entry block while the global is confirm.
	explicitBlock := &Config{
		ContextMode:       ContextModeConfirm,
		ProtectedClusters: []ProtectedCluster{{Server: "https://prod", Mode: ContextModeBlock}},
	}
	if got := explicitBlock.EffectiveClusterMode("https://prod"); got != ContextModeBlock {
		t.Errorf("explicit block = %q, want block", got)
	}
	// Explicit per-entry confirm while the global is block (override down).
	explicitConfirm := &Config{
		ContextMode:       ContextModeBlock,
		ProtectedClusters: []ProtectedCluster{{Server: "https://prod", Mode: ContextModeConfirm}},
	}
	if got := explicitConfirm.EffectiveClusterMode("https://prod"); got != ContextModeConfirm {
		t.Errorf("explicit confirm = %q, want confirm", got)
	}
	// No match falls back to the global mode.
	if got := explicitBlock.EffectiveClusterMode("https://other"); got != ContextModeConfirm {
		t.Errorf("no-match fallback = %q, want confirm (global)", got)
	}
	// Most restrictive among multiple matching entries: block wins.
	multi := &Config{
		ContextMode: ContextModeConfirm,
		ProtectedClusters: []ProtectedCluster{
			{ServerPattern: "*.example.com", Mode: ContextModeConfirm},
			{ServerPattern: "*.prod.example.com", Mode: ContextModeBlock},
		},
	}
	if got := multi.EffectiveClusterMode("https://api.prod.example.com"); got != ContextModeBlock {
		t.Errorf("most-restrictive = %q, want block", got)
	}
}

func TestAddProtectedCluster(t *testing.T) {
	c := &Config{}
	// Exact server (no glob metachar).
	if changed, err := c.AddProtectedCluster("https://prod.eks.amazonaws.com", ""); err != nil || !changed {
		t.Fatalf("add exact = (%v, %v), want (true, nil)", changed, err)
	}
	if len(c.ProtectedClusters) != 1 || c.ProtectedClusters[0].Server != "https://prod.eks.amazonaws.com" || c.ProtectedClusters[0].ServerPattern != "" {
		t.Fatalf("exact add stored wrong: %+v", c.ProtectedClusters[0])
	}
	// Pattern (has a glob metachar).
	if changed, err := c.AddProtectedCluster("*.prod.example.com", "block"); err != nil || !changed {
		t.Fatalf("add pattern = (%v, %v), want (true, nil)", changed, err)
	}
	if c.ProtectedClusters[1].ServerPattern != "*.prod.example.com" || c.ProtectedClusters[1].Server != "" || c.ProtectedClusters[1].Mode != "block" {
		t.Fatalf("pattern add stored wrong: %+v", c.ProtectedClusters[1])
	}
	// Re-add identical: no-op.
	if changed, err := c.AddProtectedCluster("*.prod.example.com", "block"); err != nil || changed {
		t.Fatalf("re-add identical = (%v, %v), want (false, nil)", changed, err)
	}
	// Re-add with a different mode: update, changed.
	if changed, err := c.AddProtectedCluster("*.prod.example.com", "confirm"); err != nil || !changed {
		t.Fatalf("re-add mode change = (%v, %v), want (true, nil)", changed, err)
	}
	if c.ProtectedClusters[1].Mode != "confirm" {
		t.Errorf("mode not updated: %q", c.ProtectedClusters[1].Mode)
	}
	// Invalid mode: error, no change.
	if changed, err := c.AddProtectedCluster("https://new", "loud"); err == nil || changed {
		t.Errorf("invalid mode = (%v, %v), want (false, error)", changed, err)
	}
	// Empty value: error.
	if changed, err := c.AddProtectedCluster("  ", ""); err == nil || changed {
		t.Errorf("empty value = (%v, %v), want (false, error)", changed, err)
	}
}

func TestRemoveProtectedCluster(t *testing.T) {
	c := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod"},
		{ServerPattern: "*.staging.example.com"},
	}}
	// Remove by raw server value.
	if !c.RemoveProtectedCluster("https://prod") {
		t.Error("remove by server value should succeed")
	}
	// Remove by display key form.
	if !c.RemoveProtectedCluster("server_pattern=*.staging.example.com") {
		t.Error("remove by key form should succeed")
	}
	if len(c.ProtectedClusters) != 0 {
		t.Errorf("expected empty after removals, got %+v", c.ProtectedClusters)
	}
	// Removing a non-existent entry.
	if c.RemoveProtectedCluster("https://nope") {
		t.Error("removing absent entry should return false")
	}
}

func TestValidateRejectsProtectedClusters(t *testing.T) {
	// Empty entry (neither server nor server_pattern).
	empty := &Config{ProtectedClusters: []ProtectedCluster{{Mode: "block"}}}
	if got := empty.Validate(); len(got) == 0 {
		t.Error("expected a problem for an empty protected_clusters entry")
	}
	// Invalid mode.
	badMode := &Config{ProtectedClusters: []ProtectedCluster{{Server: "https://prod", Mode: "loud"}}}
	problems := badMode.Validate()
	found := false
	for _, p := range problems {
		if strings.Contains(p, "invalid mode") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid-mode problem, got %v", problems)
	}
	// Valid entries produce no problems.
	ok := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod"},
		{ServerPattern: "*.prod.example.com", Mode: "block"},
	}}
	if got := ok.Validate(); len(got) != 0 {
		t.Errorf("valid clusters produced problems: %v", got)
	}
}

func TestWeakensProtectionClusters(t *testing.T) {
	old := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod", Mode: "block"},
		{ServerPattern: "*.staging.example.com"},
	}}
	old.ApplyDefaults()

	// Removal is weakening.
	removed := &Config{ProtectedClusters: []ProtectedCluster{{Server: "https://prod", Mode: "block"}}}
	removed.ApplyDefaults()
	if w := WeakensProtection(old, removed); len(w) == 0 {
		t.Error("removing a protected cluster should be weakening")
	}

	// Mode downgrade (block → confirm) is weakening.
	downgraded := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod", Mode: "confirm"},
		{ServerPattern: "*.staging.example.com"},
	}}
	downgraded.ApplyDefaults()
	w := WeakensProtection(old, downgraded)
	if len(w) == 0 {
		t.Error("downgrading a cluster mode should be weakening")
	}

	// Adding a cluster is NOT weakening.
	added := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod", Mode: "block"},
		{ServerPattern: "*.staging.example.com"},
		{Server: "https://new"},
	}}
	added.ApplyDefaults()
	if w := WeakensProtection(old, added); len(w) != 0 {
		t.Errorf("adding a cluster should not be weakening, got %v", w)
	}
}

// TestProtectedClusterYAMLRoundTrip pins that all three entry shapes marshal and
// unmarshal unchanged.
func TestProtectedClusterYAMLRoundTrip(t *testing.T) {
	orig := &Config{ProtectedClusters: []ProtectedCluster{
		{Server: "https://prod.eks.amazonaws.com"},
		{ServerPattern: "*.prod.example.com"},
		{ServerPattern: "*.staging.example.com", Mode: "block"},
	}}
	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig.ProtectedClusters, got.ProtectedClusters) {
		t.Errorf("round-trip mismatch:\n orig=%+v\n got =%+v", orig.ProtectedClusters, got.ProtectedClusters)
	}
}
