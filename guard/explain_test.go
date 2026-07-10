package guard

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestExplainFromReasons covers the decision→reason mapping for each Result via
// the internal explainFrom seam (no context/kubectl needed).
func TestExplainFromReasons(t *testing.T) {
	cfg := &config.Config{
		ProtectedContexts:  []string{"prod-*"},
		ProtectedResources: []string{"secret"},
		SensitiveAccess:    config.SensitiveAccessGate,
		BlastRadius:        config.BlastRadiusGate,
		UnknownVerb:        config.UnknownVerbGate,
	}
	cfg.ApplyDefaults()

	cases := []struct {
		name     string
		result   Result
		ctx      string
		err      error
		args     []string
		decision string
		rule     string
	}{
		{"allow read", Allow, "dev", nil, []string{"get", "pods"}, "allow", "read-only"},
		{"gate on protected context", RequireConfirmation, "prod-1", nil, []string{"delete", "pod", "x"}, "needs-confirmation", "protected-context"},
		{"gate sensitive unprotected", RequireConfirmation, "dev", nil, []string{"exec", "pod", "--", "sh"}, "needs-confirmation", "sensitive-access"},
		{"gate blast unprotected", RequireConfirmation, "dev", nil, []string{"delete", "pods", "--all"}, "needs-confirmation", "blast-radius"},
		{"gate unknown", RequireConfirmation, "dev", nil, []string{"my-plugin", "sync"}, "needs-confirmation", "unknown-verb"},
		{"blocked resource", Blocked, "dev", nil, []string{"get", "secret", "db"}, "blocked", "protected-resource"},
		{"denied", Deny, "", errors.New("cannot resolve current context"), []string{"delete", "pod"}, "denied", "fail-closed"},
		{"setup", SetupRequired, "", nil, []string{"get", "pods"}, "setup-required", "no-config"},
		{"dry-run skip", Allow, "prod-1", nil, []string{"delete", "pod", "x", "--dry-run=client"}, "allow", "dry-run-skip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := explainFrom(tc.result, tc.ctx, cfg, tc.err, tc.args)
			if r.Decision != tc.decision {
				t.Errorf("decision = %q, want %q", r.Decision, tc.decision)
			}
			if r.Rule != tc.rule {
				t.Errorf("rule = %q, want %q (reason: %q)", r.Rule, tc.rule, r.Reason)
			}
			if r.Reason == "" {
				t.Error("reason should never be empty")
			}
		})
	}
}

// TestExplainClass reports the verb classification.
func TestExplainClass(t *testing.T) {
	cfg := &config.Config{}
	cfg.ApplyDefaults()
	if got := explainFrom(Allow, "dev", cfg, nil, []string{"get", "pods"}).Class; got != "safe" {
		t.Errorf("get class = %q, want safe", got)
	}
	if got := explainFrom(RequireConfirmation, "dev", cfg, nil, []string{"delete", "pod"}).Class; got != "state-altering" {
		t.Errorf("delete class = %q, want state-altering", got)
	}
	if got := explainFrom(Allow, "dev", cfg, nil, []string{"my-plugin"}).Class; got != "unknown" {
		t.Errorf("my-plugin class = %q, want unknown", got)
	}
}

// TestExplainResultJSON: the JSON shape matches the runtime JSONResult fields,
// and the reason field carries the machine-readable RULE (not the prose).
func TestExplainResultJSON(t *testing.T) {
	r := ExplainResult{Decision: "blocked", Rule: "protected-resource", Reason: "targets protected resource \"secret\"", Context: "prod-1", Resource: "secret"}
	b, err := json.Marshal(r.JSONResult("get secret db"))
	if err != nil {
		t.Fatal(err)
	}
	var back JSONResult
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Decision != "blocked" || back.Command != "get secret db" || back.Resource != "secret" || back.Context != "prod-1" {
		t.Errorf("round-trip mismatch: %+v", back)
	}
	if back.Reason != "protected-resource" {
		t.Errorf("JSON reason = %q, want the machine rule token 'protected-resource'", back.Reason)
	}
}

// TestExplainWritesNoAudit: Explain must be a pure query — it must not write an
// audit entry (Check never audits, but pin it).
func TestExplainWritesNoAudit(t *testing.T) {
	dir := t.TempDir()
	orig := os.Getenv("HOME")
	_ = os.Setenv("HOME", dir)
	defer func() { _ = os.Setenv("HOME", orig) }()

	cfg := &config.Config{ProtectedContexts: []string{"prod-*"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// End-to-end: Explain returns a valid decision (the switch on Check's Result)
	// without depending on how context resolution behaves in the test environment.
	res := Explain([]string{"delete", "pod", "x"})
	switch res.Decision {
	case "allow", "needs-confirmation", "blocked", "denied", "setup-required":
	default:
		t.Errorf("Explain returned an invalid decision %q", res.Decision)
	}
	if res.Reason == "" || res.Rule == "" {
		t.Errorf("Explain must populate reason and rule; got %+v", res)
	}

	if _, err := os.Stat(filepath.Join(dir, ".kubectl-guard-audit.log")); !os.IsNotExist(err) {
		t.Errorf("Explain must not write an audit log; stat err = %v", err)
	}
}
