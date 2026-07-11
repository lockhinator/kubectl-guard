package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// secretRawPath is the exact read that motivated #80: it returns the secret's
// value while never mentioning "secret" as a resource token.
const secretRawPath = "/api/v1/namespaces/default/secrets/db-creds"

// TestParseArgsRaw: --raw is value-taking in both forms, so its path never
// lands in the positional (resource candidate) stream.
func TestParseArgsRaw(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantHasRaw     bool
		wantRaw        string
		wantPositional []string
	}{
		{"separate value", []string{"get", "--raw", secretRawPath}, true, secretRawPath, []string{"get"}},
		{"inline value", []string{"get", "--raw=" + secretRawPath}, true, secretRawPath, []string{"get"}},
		{"healthz", []string{"get", "--raw", "/healthz"}, true, "/healthz", []string{"get"}},
		{"no raw", []string{"get", "pods"}, false, "", []string{"get", "pods"}},
		{"raw with create", []string{"create", "--raw", "/api/v1/namespaces/x/secrets", "-f", "s.json"}, true, "/api/v1/namespaces/x/secrets", []string{"create"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ParseArgs(tt.args)
			if p.HasRaw != tt.wantHasRaw {
				t.Errorf("HasRaw = %v, want %v", p.HasRaw, tt.wantHasRaw)
			}
			if p.Raw != tt.wantRaw {
				t.Errorf("Raw = %q, want %q", p.Raw, tt.wantRaw)
			}
			if len(p.Positional) != len(tt.wantPositional) {
				t.Fatalf("Positional = %v, want %v", p.Positional, tt.wantPositional)
			}
			for i := range tt.wantPositional {
				if p.Positional[i] != tt.wantPositional[i] {
					t.Errorf("Positional = %v, want %v", p.Positional, tt.wantPositional)
				}
			}
		})
	}
}

// TestRawBlockedWhenResourceProtected covers the headline #80 criterion: the
// raw secret read is blocked when resource protection is configured — including
// when the protected resource is something other than "secret", since the guard
// cannot prove what the path resolves to.
func TestRawBlockedWhenResourceProtected(t *testing.T) {
	tests := []struct {
		name      string
		protected []string
		args      []string
	}{
		{"secret protected, raw secret path", []string{"secret"}, []string{"get", "--raw", secretRawPath}},
		{"secret protected, inline raw", []string{"secret"}, []string{"get", "--raw=" + secretRawPath}},
		{"configmap protected, raw secret path", []string{"configmap"}, []string{"get", "--raw", secretRawPath}},
		{"secret protected, innocuous raw path", []string{"secret"}, []string{"get", "--raw", "/healthz"}},
		{"raw serviceaccount token", []string{"secret"}, []string{"get", "--raw", "/api/v1/namespaces/default/serviceaccounts/deployer/token"}},
		{"create --raw is a write vector", []string{"secret"}, []string{"create", "--raw", "/api/v1/namespaces/x/secrets", "-f", "s.json"}},
		{"delete --raw", []string{"secret"}, []string{"delete", "--raw", secretRawPath}},
		{"replace --raw", []string{"secret"}, []string{"replace", "--raw", secretRawPath, "-f", "s.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{ProtectedResources: tt.protected}
			if !MatchesProtectedResource(cfg, tt.args) {
				t.Errorf("MatchesProtectedResource(%v) = false, want true", tt.args)
			}
		})
	}
}

// TestRawAllowedWhenNoResourceProtection: with no resource protection, --raw is
// untouched — /healthz, /version and friends keep working.
func TestRawAllowedWhenNoResourceProtection(t *testing.T) {
	for _, args := range [][]string{
		{"get", "--raw", "/healthz"},
		{"get", "--raw", "/version"},
		{"get", "--raw=" + secretRawPath},
	} {
		cfg := &config.Config{} // no protected resources
		if MatchesProtectedResource(cfg, args) {
			t.Errorf("MatchesProtectedResource(%v) = true, want false (no resource protection)", args)
		}
	}
}

// TestRawCheckLevelBlocked drives the real decision path: a raw secret read on
// an UNPROTECTED context must still be Blocked, because resource protection is
// global and independent of context.
func TestRawCheckLevelBlocked(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedResources: []string{"secret"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"get", "--raw", secretRawPath}, staticContext("dev-cluster"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked", res)
	}
}

// TestRawCheckLevelHealthzAllowed: /healthz with no resource protection passes.
func TestRawCheckLevelHealthzAllowed(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"get", "--raw", "/healthz"}, staticContext("prod-cluster"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (read-only, no resource protection)", res)
	}
}

// TestNormalizeResourceEmptiesAPIPaths documents WHY the --raw handling exists:
// NormalizeResource cannot represent an API path. It strips at the first "/" and
// returns "", which IsResourceProtected then reports as "not protected". Any
// code path that lets an API path reach resource matching therefore fails OPEN.
func TestNormalizeResourceEmptiesAPIPaths(t *testing.T) {
	if got := config.NormalizeResource(secretRawPath); got != "" {
		t.Errorf("NormalizeResource(%q) = %q, want \"\" (documents the trap)", secretRawPath, got)
	}
	cfg := &config.Config{ProtectedResources: []string{"secret"}}
	if cfg.IsResourceProtected(secretRawPath) {
		t.Errorf("IsResourceProtected(%q) = true; test premise is wrong", secretRawPath)
	}
}

// TestAPIPathInResourcePositionBlocked: even if an API path reaches resource
// matching as a positional (not via --raw), it must not slip through as a
// silent non-match. Fail closed instead.
func TestAPIPathInResourcePositionBlocked(t *testing.T) {
	cfg := &config.Config{ProtectedResources: []string{"secret"}}
	args := []string{"get", secretRawPath}
	if !MatchesProtectedResource(cfg, args) {
		t.Errorf("MatchesProtectedResource(%v) = false, want true (API path must not slip through)", args)
	}
}

// TestNormalGetUnchanged: the --raw work must not alter ordinary behavior.
func TestNormalGetUnchanged(t *testing.T) {
	cfg := &config.Config{ProtectedResources: []string{"secret"}}
	if !MatchesProtectedResource(cfg, []string{"get", "secret", "db"}) {
		t.Error("get secret should still be blocked")
	}
	if MatchesProtectedResource(cfg, []string{"get", "pods"}) {
		t.Error("get pods must not be blocked")
	}
	if MatchesProtectedResource(cfg, []string{"describe", "pod", "nginx"}) {
		t.Error("describe pod must not be blocked")
	}
	// A pod literally named "raw" is not a --raw flag.
	if MatchesProtectedResource(cfg, []string{"get", "pod", "raw"}) {
		t.Error("a pod named \"raw\" must not be blocked")
	}
}

// TestRawAfterDoubleDashIsNotAFlag: tokens after "--" are positional kubectl
// args, so a literal "--raw" there must not be parsed as the guard's flag.
func TestRawAfterDoubleDashIsNotAFlag(t *testing.T) {
	p := ParseArgs([]string{"exec", "pod", "--", "sh", "-c", "--raw"})
	if p.HasRaw {
		t.Error("--raw after \"--\" must not be treated as a flag")
	}
}

// TestExecPayloadPathsNotTreatedAsAPIPaths: the API-path rule applies only to
// kubectl resource tokens (before "--"). An absolute path in an exec payload is
// a filesystem path in the container, not an API path, and blocking it would
// make `kubectl exec nginx -- ls /tmp` fail whenever any resource is protected.
func TestExecPayloadPathsNotTreatedAsAPIPaths(t *testing.T) {
	cfg := &config.Config{ProtectedResources: []string{"secret"}}
	for _, args := range [][]string{
		{"exec", "nginx", "--", "ls", "/tmp"},
		{"exec", "nginx", "--", "cat", "/etc/hosts"},
		{"exec", "nginx", "--", "/bin/sh", "-c", "echo hi"},
		{"run", "x", "--image=busybox", "--", "/bin/sh"},
	} {
		if MatchesProtectedResource(cfg, args) {
			t.Errorf("MatchesProtectedResource(%v) = true, want false (payload path, not an API path)", args)
		}
	}
}

// TestPositionalsBeforeSep records the separator boundary the API-path rule
// depends on.
func TestPositionalsBeforeSep(t *testing.T) {
	tests := []struct {
		args []string
		want int
	}{
		{[]string{"get", "pods"}, 2},
		{[]string{"exec", "nginx", "--", "ls", "/tmp"}, 2},
		{[]string{"exec", "nginx", "-c", "app", "--", "sh"}, 2},
		{[]string{"delete", "--", "secret", "db"}, 1},
		{[]string{"get"}, 1},
		{[]string{}, 0},
	}
	for _, tt := range tests {
		if got := ParseArgs(tt.args).PositionalsBeforeSep; got != tt.want {
			t.Errorf("ParseArgs(%v).PositionalsBeforeSep = %d, want %d", tt.args, got, tt.want)
		}
	}
}

// TestResourceTokenAfterSeparatorStillMatched: H4 — a real resource token after
// "--" must still be matched by name (only the API-path rule is scoped).
func TestResourceTokenAfterSeparatorStillMatched(t *testing.T) {
	cfg := &config.Config{ProtectedResources: []string{"secret"}}
	if !MatchesProtectedResource(cfg, []string{"delete", "--", "secret", "db"}) {
		t.Error("a protected resource token after \"--\" must still be blocked (H4)")
	}
}
