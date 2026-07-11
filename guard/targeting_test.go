package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// staticContext returns a CurrentContextFunc that always reports ctx.
func staticContext(ctx string) CurrentContextFunc {
	return func(string) (string, error) { return ctx, nil }
}

// TestParseArgsServerLong captures --server and keeps its value out of positionals.
func TestParseArgsServerLong(t *testing.T) {
	args := []string{"--server=https://evil:6443", "delete", "pod", "nginx"}
	p := ParseArgs(args)
	if !p.HasServer {
		t.Fatal("ParseArgs did not capture --server")
	}
	if p.Server != "https://evil:6443" {
		t.Errorf("Server = %q, want https://evil:6443", p.Server)
	}
}

// TestParseArgsServerShort captures -s value (separate arg).
func TestParseArgsServerShort(t *testing.T) {
	p := ParseArgs([]string{"-s", "https://api:6443", "get", "pods"})
	if !p.HasServer || p.Server != "https://api:6443" {
		t.Errorf("server = %q (has=%v), want https://api:6443", p.Server, p.HasServer)
	}
	if len(p.Positional) != 2 || p.Positional[0] != "get" {
		t.Errorf("Positional = %v, want [get pods]", p.Positional)
	}
}

// TestParseArgsServerShortAttached captures -sURL.
func TestParseArgsServerShortAttached(t *testing.T) {
	p := ParseArgs([]string{"-shttps://api:6443", "get", "pods"})
	if !p.HasServer || p.Server != "https://api:6443" {
		t.Errorf("server = %q (has=%v)", p.Server, p.HasServer)
	}
}

// TestParseArgsIdentityFlags captures --as / --as-group / --as-uid / --token.
func TestParseArgsIdentityFlags(t *testing.T) {
	p := ParseArgs([]string{"--as=system:admin", "--as-group", "devs", "--as-group=sres", "--as-uid=abc", "--token", "tok", "get", "pods"})
	if !p.HasImpersonation() {
		t.Error("HasImpersonation = false, want true")
	}
	if p.AsUser != "system:admin" {
		t.Errorf("AsUser = %q", p.AsUser)
	}
	if len(p.AsGroups) != 2 || p.AsGroups[0] != "devs" || p.AsGroups[1] != "sres" {
		t.Errorf("AsGroups = %v", p.AsGroups)
	}
	if p.AsUID != "abc" {
		t.Errorf("AsUID = %q", p.AsUID)
	}
	if !p.HasToken || p.Token != "tok" {
		t.Errorf("Token = %q (has=%v)", p.Token, p.HasToken)
	}
}

// TestImpersonationString: the audit summary attributes --as, --as-group, and
// --as-uid, including group- or uid-only impersonation (which previously left
// the audit Impersonate field empty).
func TestImpersonationString(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"as only", []string{"--as=system:admin", "get", "pods"}, "system:admin"},
		{"group only", []string{"--as-group=system:masters", "delete", "pod", "x"}, "group:system:masters"},
		{"uid only", []string{"--as-uid=0", "delete", "pod", "x"}, "uid:0"},
		{"combined", []string{"--as=alice", "--as-group=devs", "--as-uid=42", "get", "pods"}, "alice,group:devs,uid:42"},
		{"none", []string{"get", "pods"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseArgs(tt.args).ImpersonationString(); got != tt.want {
				t.Errorf("ImpersonationString(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

// TestParseArgsNoIdentityFlags: without identity flags, HasImpersonation/HasToken are false.
func TestParseArgsNoIdentityFlags(t *testing.T) {
	p := ParseArgs([]string{"get", "pods"})
	if p.HasImpersonation() {
		t.Error("HasImpersonation = true, want false")
	}
	if p.HasToken {
		t.Error("HasToken = true, want false")
	}
}

// --- checkWith-level decision tests (use the package's withTempHome helper) ---

// TestCheckServerDeniesWhenContextsProtected: --server with protected contexts
// configured must fail closed (Deny). Reverting the --server check makes this
// resolve the current context and return RequireConfirmation/Allow.
func TestCheckServerDeniesWhenContextsProtected(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, err := checkWith([]string{"--server=https://evil:6443", "delete", "pod", "nginx"}, staticContext("dev"))
	if res != Deny {
		t.Errorf("result = %v, want Deny", res)
	}
	if err == nil {
		t.Error("expected a non-nil error explaining --server")
	}
}

// TestCheckServerAllowedWhenNoContextsProtected: no protected contexts -> --server
// has nothing to enforce; allow.
func TestCheckServerAllowedWhenNoContextsProtected(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--server=https://evil:6443", "get", "pods"}, staticContext("dev"))
	if res != Allow {
		t.Errorf("result = %v, want Allow", res)
	}
}

// TestCheckBlockImpersonationPolicy: block_impersonation on a protected context
// denies any --as command (even a read).
func TestCheckBlockImpersonationPolicy(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:  config.Patterns("prod-*"),
		BlockImpersonation: true,
	})
	defer cleanup()
	res, _, _, err := checkWith([]string{"--context=prod-cluster", "--as=system:admin", "get", "pods"}, staticContext("prod-cluster"))
	if res != Deny {
		t.Errorf("result = %v, want Deny (err=%v)", res, err)
	}
}

// TestCheckImpersonationAllowedWhenPolicyOff: default (policy off) -> --as on a
// protected read-only command is allowed (unchanged).
func TestCheckImpersonationAllowedWhenPolicyOff(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "--as=dev", "get", "pods"}, staticContext("prod-cluster"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (impersonation policy off)", res)
	}
}

// TestCheckNormalCommandsUnaffected: no targeting/identity flags -> a
// state-altering command on a protected context still requires confirmation.
func TestCheckNormalCommandsUnaffected(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation", res)
	}
}
