package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// accessVerbCommands are the high-risk access vectors gated by #71. They mutate
// nothing but open a live channel into the cluster with the caller's
// credentials, so they must gate exactly like a state-altering command.
var accessVerbCommands = map[string][]string{
	"port-forward": {"port-forward", "svc/prod-postgres", "5432:5432"},
	"proxy":        {"proxy"},
}

// TestAccessVerbsRequireConfirmationOnProtectedContext: port-forward/proxy on a
// protected context must prompt rather than pass through silently.
func TestAccessVerbsRequireConfirmationOnProtectedContext(t *testing.T) {
	for name, args := range accessVerbCommands {
		t.Run(name, func(t *testing.T) {
			cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
			defer cleanup()
			res, _, _, _ := checkWith(args, staticContext("prod-cluster"))
			if res != RequireConfirmation {
				t.Errorf("result = %v, want RequireConfirmation", res)
			}
		})
	}
}

// TestAccessVerbsBlockedInBlockMode: with context_mode: block, the same
// commands are hard-refused with no confirmation offered.
func TestAccessVerbsBlockedInBlockMode(t *testing.T) {
	for name, args := range accessVerbCommands {
		t.Run(name, func(t *testing.T) {
			cleanup := withTempHome(t, &config.Config{
				ProtectedContexts: []string{"prod-*"},
				ContextMode:       config.ContextModeBlock,
			})
			defer cleanup()
			res, _, _, _ := checkWith(args, staticContext("prod-cluster"))
			if res != Blocked {
				t.Errorf("result = %v, want Blocked", res)
			}
		})
	}
}

// TestAccessVerbsGatedOnProtectedNamespace: namespace protection gates them too,
// independently of context protection.
func TestAccessVerbsGatedOnProtectedNamespace(t *testing.T) {
	for name, base := range accessVerbCommands {
		t.Run(name, func(t *testing.T) {
			cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"prod"}})
			defer cleanup()
			args := append([]string{"-n", "prod"}, base...)
			res, _, _, _ := checkWith(args, staticContext("dev-cluster"))
			if res != RequireConfirmation {
				t.Errorf("result = %v, want RequireConfirmation", res)
			}
		})
	}
}

// TestAccessVerbsPassOnUnprotectedContext: on an unprotected context the
// commands are unchanged — they pass through (and are audited by the caller).
func TestAccessVerbsPassOnUnprotectedContext(t *testing.T) {
	for name, args := range accessVerbCommands {
		t.Run(name, func(t *testing.T) {
			cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
			defer cleanup()
			res, _, _, _ := checkWith(args, staticContext("dev-cluster"))
			if res != Allow {
				t.Errorf("result = %v, want Allow", res)
			}
		})
	}
}

// TestAccessVerbsDryRunCannotSkipGating: these verbs have no --dry-run, so a
// --dry-run token must not buy the ungated pass a real dry-run would. Otherwise
// the guard's fail-closed posture would depend on kubectl rejecting the flag.
func TestAccessVerbsDryRunCannotSkipGating(t *testing.T) {
	for name, base := range accessVerbCommands {
		t.Run(name, func(t *testing.T) {
			cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
			defer cleanup()
			args := append([]string{"--dry-run=client"}, base...)
			res, _, _, _ := checkWith(args, staticContext("prod-cluster"))
			if res != RequireConfirmation {
				t.Errorf("result = %v, want RequireConfirmation (dry-run must not skip gating)", res)
			}
		})
	}
}

// TestSupportsDryRun documents which verbs may use a dry-run to skip gating.
// Membership mirrors `kubectl <verb> --help` (v1.33): a verb that has no
// --dry-run flag can never be dry-run, so it must always gate.
func TestSupportsDryRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"apply", []string{"apply", "-f", "x.yaml"}, true},
		{"delete", []string{"delete", "pod", "nginx"}, true},
		{"create", []string{"create", "deployment", "nginx"}, true},
		{"drain", []string{"drain", "node1"}, true},
		{"auth reconcile", []string{"auth", "reconcile", "-f", "rbac.yaml"}, true},
		{"rollout undo", []string{"rollout", "undo", "deployment/nginx"}, true},

		{"exec", []string{"exec", "nginx", "--", "ls"}, false},
		{"cp", []string{"cp", "nginx:/tmp/f", "./f"}, false},
		{"attach", []string{"attach", "nginx"}, false},
		{"debug", []string{"debug", "nginx"}, false},
		{"port-forward", []string{"port-forward", "svc/db", "5432:5432"}, false},
		{"proxy", []string{"proxy"}, false},
		{"edit", []string{"edit", "deployment", "nginx"}, false},
		{"config use-context", []string{"config", "use-context", "prod"}, false},
		{"certificate approve", []string{"certificate", "approve", "my-csr"}, false},
		{"certificate deny", []string{"certificate", "deny", "my-csr"}, false},
		{"rollout restart", []string{"rollout", "restart", "deployment/nginx"}, false},
		{"rollout pause", []string{"rollout", "pause", "deployment/nginx"}, false},
		{"rollout resume", []string{"rollout", "resume", "deployment/nginx"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupportsDryRun(tt.args); got != tt.want {
				t.Errorf("SupportsDryRun(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// TestEditDryRunCannotSkipGating: `kubectl edit` has no --dry-run, so a
// --dry-run token must not skip gating on a protected context.
func TestEditDryRunCannotSkipGating(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"edit", "deployment", "nginx", "--dry-run=client"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation", res)
	}
}

// verbShiftBypasses are argv forms where a kubectl GLOBAL flag takes a
// space-separated value. If the guard does not consume that value, the value
// lands in verb position and the real verb is never classified — an ungated
// fail-open (the S3 verb-shift bypass). Every one of these was confirmed to
// return Allow before the fix, and each flag is a real kubectl global flag
// (verified against `kubectl options`, v1.33).
var verbShiftBypasses = map[string][]string{
	"-v short":          {"-v", "3", "port-forward", "svc/prod-db", "5432:5432"},
	"-v short zero":     {"-v", "0", "proxy"},
	"--v long":          {"--v", "3", "port-forward", "svc/prod-db", "5432:5432"},
	"--profile":         {"--profile", "none", "port-forward", "svc/prod-db", "5432:5432"},
	"--request-timeout": {"--request-timeout", "30", "delete", "pod", "nginx"},
	"--cache-dir":       {"--cache-dir", "/tmp/c", "delete", "pod", "nginx"},
	"--tls-server-name": {"--tls-server-name", "x", "exec", "nginx", "--", "sh"},
	"--username":        {"--username", "admin", "apply", "-f", "x.yaml"},
	// The flag values here are arbitrary placeholders: these cases assert only
	// that the flag CONSUMES its value, so the verb after it is still seen.
	"--password":              {"--password", "pw-placeholder", "delete", "pod", "nginx"},
	"--client-key":            {"--client-key", "/tmp/k", "proxy"},
	"--log-flush-freq":        {"--log-flush-frequency", "5s", "delete", "pod", "nginx"},
	"--vmodule":               {"--vmodule", "x=1", "delete", "pod", "nginx"},
	"--profile-output":        {"--profile-output", "p.pprof", "proxy"},
	"--client-certificate":    {"--client-certificate", "/tmp/c", "delete", "pod", "nginx"},
	"--certificate-authority": {"--certificate-authority", "/tmp/ca", "delete", "pod", "nginx"},
}

// TestVerbShiftCannotBypassGating locks S3 closed: a global flag's value must
// never be mistaken for the verb, hiding a gated verb from classification.
func TestVerbShiftCannotBypassGating(t *testing.T) {
	for name, args := range verbShiftBypasses {
		t.Run(name, func(t *testing.T) {
			cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
			defer cleanup()
			res, _, _, _ := checkWith(args, staticContext("prod-cluster"))
			if res != RequireConfirmation {
				t.Errorf("checkWith(%v) = %v, want RequireConfirmation (verb-shift bypass)", args, res)
			}
		})
	}
}

// TestVerbShiftExtractsRealVerb: the parser must consume each global flag's
// value so the real verb reaches classification.
func TestVerbShiftExtractsRealVerb(t *testing.T) {
	for name, args := range verbShiftBypasses {
		t.Run(name, func(t *testing.T) {
			if !IsStateAltering(args) {
				cmd, _ := ExtractCommand(args)
				t.Errorf("IsStateAltering(%v) = false (verb resolved to %q), want true", args, cmd)
			}
		})
	}
}

// TestBooleanGlobalFlagsDoNotSwallowVerb: kubectl's boolean global flags
// consume no value. If the guard treated them as value-taking, they would eat
// the verb — the mirror-image bug of the verb shift, and equally fail-open.
func TestBooleanGlobalFlagsDoNotSwallowVerb(t *testing.T) {
	boolGlobals := []string{
		"--insecure-skip-tls-verify", "--disable-compression",
		"--match-server-version", "--warnings-as-errors",
	}
	for _, flag := range boolGlobals {
		t.Run(flag, func(t *testing.T) {
			args := []string{flag, "delete", "pod", "nginx"}
			cmd, _ := ExtractCommand(args)
			if cmd != "delete" {
				t.Errorf("ExtractCommand(%v) = %q, want \"delete\"", args, cmd)
			}
			if !IsStateAltering(args) {
				t.Errorf("IsStateAltering(%v) = false, want true", args)
			}
		})
	}
}

// TestUnrecognizedVerbFallsBackFailClosed: if a future kubectl global flag is
// missing from knownLongFlags, its value shifts into verb position. The guard
// must then fall back to the first recognized verb later in the stream rather
// than classify the stray value as an unknown (ungated) command.
func TestUnrecognizedVerbFallsBackFailClosed(t *testing.T) {
	// "--future-flag" is deliberately unknown to the guard, simulating a global
	// flag added by a later kubectl.
	args := []string{"--future-flag", "somevalue", "delete", "pod", "nginx"}
	cmd, _ := ExtractCommand(args)
	if cmd != "delete" {
		t.Errorf("ExtractCommand(%v) = %q, want \"delete\" (fail-closed fallback)", args, cmd)
	}
	if !IsStateAltering(args) {
		t.Errorf("IsStateAltering(%v) = false, want true", args)
	}
}

// TestUnknownVerbStaysUnknown: the fail-closed fallback must not over-gate a
// command that has no recognized verb at all (a plugin, `completion`, ...).
func TestUnknownVerbStaysUnknown(t *testing.T) {
	for _, args := range [][]string{
		{"completion", "bash"},
		{"krew", "install", "foo"},
		{"options"},
	} {
		if IsStateAltering(args) {
			t.Errorf("IsStateAltering(%v) = true, want false (no recognized verb)", args)
		}
	}
}

// TestReadVerbNotOverGatedAfterShift: a shifted READ verb must still resolve to
// the read verb, not be mistaken for a gated one.
func TestReadVerbNotOverGatedAfterShift(t *testing.T) {
	args := []string{"-v", "3", "get", "pods"}
	cmd, _ := ExtractCommand(args)
	if cmd != "get" {
		t.Errorf("ExtractCommand(%v) = %q, want \"get\"", args, cmd)
	}
	if IsStateAltering(args) {
		t.Errorf("IsStateAltering(%v) = true, want false", args)
	}
}

// TestApplyDryRunStillSkipsGating guards against the #71 dry-run exclusion
// regressing the existing behavior for verbs that genuinely support --dry-run.
func TestApplyDryRunStillSkipsGating(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"apply", "--dry-run=client", "-f", "deploy.yaml"}, staticContext("prod-cluster"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (a real dry-run still skips gating)", res)
	}
}

// TestCertificateApproveGatedOnProtectedContext locks down the hole where
// `certificate approve` (credential issuance) bypassed even a configured guard,
// because it was classified as a read.
func TestCertificateApproveGatedOnProtectedContext(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"certificate", "approve", "my-csr"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation", res)
	}
}

// TestCertificateDryRunCannotSkipGating: `certificate approve` has no --dry-run
// flag, so a --dry-run token must not buy the ungated pass a real dry-run would.
func TestCertificateDryRunCannotSkipGating(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"certificate", "approve", "--dry-run=client", "my-csr"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (dry-run must not skip gating)", res)
	}
}

// TestCertificateBlockedInBlockMode: block mode hard-refuses it.
func TestCertificateBlockedInBlockMode(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		ContextMode:       config.ContextModeBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"certificate", "deny", "my-csr"}, staticContext("prod-cluster"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked", res)
	}
}
