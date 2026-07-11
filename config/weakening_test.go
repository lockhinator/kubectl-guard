package config

import (
	"strings"
	"testing"
)

func TestWeakensProtection(t *testing.T) {
	base := func() *Config {
		c := &Config{
			ProtectedContexts:   Patterns("prod-*"),
			ProtectedResources:  []string{"secret"},
			ProtectedNamespaces: Patterns("kube-system"),
			ContextMode:         ContextModeBlock,
			SensitiveAccess:     SensitiveAccessBlock,
			BlastRadius:         BlastRadiusGate,
			UnknownVerb:         UnknownVerbDeny,
			AuditMode:           AuditModeAll,
			BlockImpersonation:  true,
		}
		c.ApplyDefaults()
		return c
	}

	cases := []struct {
		name       string
		mutate     func(*Config)
		wantWeaken bool
		wantSubstr string
	}{
		{"remove protected resource", func(c *Config) { c.ProtectedResources = nil }, true, "removed protected resource: secret"},
		{"remove protected context", func(c *Config) { c.ProtectedContexts = nil }, true, "removed protected context"},
		{"remove protected namespace", func(c *Config) { c.ProtectedNamespaces = nil }, true, "removed protected namespace"},
		{"downgrade context_mode", func(c *Config) { c.ContextMode = ContextModeConfirm }, true, "context_mode"},
		{"downgrade sensitive_access", func(c *Config) { c.SensitiveAccess = SensitiveAccessOff }, true, "sensitive_access"},
		{"downgrade blast_radius", func(c *Config) { c.BlastRadius = BlastRadiusOff }, true, "blast_radius"},
		{"downgrade unknown_verb", func(c *Config) { c.UnknownVerb = UnknownVerbAllow }, true, "unknown_verb"},
		{"audit-mode off", func(c *Config) { c.AuditMode = AuditModeOff }, true, "audit_mode"},
		{"disable block_impersonation", func(c *Config) { c.BlockImpersonation = false }, true, "block_impersonation"},
		{"mark verb safe", func(c *Config) { c.CommandOverrides.Safe = []string{"delete"} }, true, "marked verb safe"},

		// Strengthening / additive → NOT weakening.
		{"add protected resource", func(c *Config) { c.ProtectedResources = append(c.ProtectedResources, "configmap") }, false, ""},
		{"add protected context", func(c *Config) { c.ProtectedContexts = append(c.ProtectedContexts, ProtectedPattern{Pattern: "stg-*"}) }, false, ""},
		{"upgrade blast_radius", func(c *Config) { c.BlastRadius = BlastRadiusBlock }, false, ""},
		{"enable something stricter", func(c *Config) { c.UnknownVerb = UnknownVerbDeny }, false, ""}, // no change
		{"no change", func(c *Config) {}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := base()
			newCfg := base()
			tc.mutate(newCfg)
			w := WeakensProtection(old, newCfg)
			if tc.wantWeaken && len(w) == 0 {
				t.Errorf("expected weakening, got none")
			}
			if !tc.wantWeaken && len(w) != 0 {
				t.Errorf("expected no weakening, got %v", w)
			}
			if tc.wantSubstr != "" {
				found := false
				for _, item := range w {
					if strings.Contains(item, tc.wantSubstr) {
						found = true
					}
				}
				if !found {
					t.Errorf("weakening %v does not mention %q", w, tc.wantSubstr)
				}
			}
		})
	}
}

// TestWeakensProtectionAuditShipping: removing an audit webhook or disabling
// syslog reduces audit coverage and is weakening.
func TestWeakensProtectionAuditShipping(t *testing.T) {
	old := &Config{AuditWebhookURL: "https://siem/hook", AuditSyslog: true}
	old.ApplyDefaults()
	newCfg := &Config{}
	newCfg.ApplyDefaults()
	w := WeakensProtection(old, newCfg)
	joined := strings.Join(w, "; ")
	if !strings.Contains(joined, "audit_webhook_url") || !strings.Contains(joined, "audit_syslog") {
		t.Errorf("removing webhook + disabling syslog should weaken; got %v", w)
	}
}

// TestWeakensProtectionWebhookRedirect: changing a configured webhook URL (a
// redirect, not just clearing it) defeats audit shipping and is weakening.
func TestWeakensProtectionWebhookRedirect(t *testing.T) {
	old := &Config{AuditWebhookURL: "https://siem.example/hook"}
	old.ApplyDefaults()
	// Redirect to a different endpoint.
	redir := &Config{AuditWebhookURL: "http://127.0.0.1:1/collector"}
	redir.ApplyDefaults()
	if w := WeakensProtection(old, redir); len(w) == 0 {
		t.Error("redirecting a configured webhook should weaken")
	}
	// Setting a webhook for the first time is NOT weakening.
	empty := &Config{}
	empty.ApplyDefaults()
	if w := WeakensProtection(empty, old); len(w) != 0 {
		t.Errorf("setting a webhook for the first time should not weaken; got %v", w)
	}
}

// TestWeakensProtectionRotationShrink: shrinking the audit rotation retention
// (smaller size cap or fewer archives) evicts history and is weakening; disabling
// rotation entirely (→ unbounded) is not.
func TestWeakensProtectionRotationShrink(t *testing.T) {
	old := &Config{AuditMaxSizeMB: 50, AuditMaxFiles: 10}
	old.ApplyDefaults()
	shrink := &Config{AuditMaxSizeMB: 1, AuditMaxFiles: 1}
	shrink.ApplyDefaults()
	if w := WeakensProtection(old, shrink); len(w) == 0 {
		t.Error("shrinking rotation retention should weaken")
	}
	// Disabling rotation (→0, unbounded) is not a reduction.
	off := &Config{AuditMaxSizeMB: 0, AuditMaxFiles: 0}
	off.ApplyDefaults()
	if w := WeakensProtection(old, off); len(w) != 0 {
		t.Errorf("disabling rotation (unbounded) should not weaken; got %v", w)
	}
	// Introducing a TIGHT cap where the log was previously unbounded evicts
	// history — also weakening (the from-unbounded edge).
	unbounded := &Config{AuditMaxSizeMB: 0}
	unbounded.ApplyDefaults()
	tight := &Config{AuditMaxSizeMB: 1, AuditMaxFiles: 1}
	tight.ApplyDefaults()
	if w := WeakensProtection(unbounded, tight); len(w) == 0 {
		t.Error("introducing a tight rotation cap from unbounded should weaken")
	}
	// Enlarging retention (more archives) is not weakening.
	bigger := &Config{AuditMaxSizeMB: 50, AuditMaxFiles: 20}
	bigger.ApplyDefaults()
	if w := WeakensProtection(old, bigger); len(w) != 0 {
		t.Errorf("enlarging retention should not weaken; got %v", w)
	}
}

// TestWeakensProtectionConfirmModeAgentRelay: type-name → agent-relay is not a
// downgrade (agent-relay relays rather than auto-approves); type-name → simple is.
func TestWeakensProtectionConfirmModeAgentRelay(t *testing.T) {
	old := &Config{ConfirmMode: ConfirmModeTypeName}
	old.ApplyDefaults()
	relay := &Config{ConfirmMode: ConfirmModeAgentRelay}
	relay.ApplyDefaults()
	if w := WeakensProtection(old, relay); len(w) != 0 {
		t.Errorf("type-name → agent-relay should not weaken; got %v", w)
	}
	simple := &Config{ConfirmMode: ConfirmModeSimple}
	simple.ApplyDefaults()
	if w := WeakensProtection(old, simple); len(w) == 0 {
		t.Error("type-name → simple should weaken")
	}
}

// TestWeakensProtectionActorPolicy: removing an actor policy or downgrading its
// mode from block is weakening.
func TestWeakensProtectionActorPolicy(t *testing.T) {
	old := &Config{ActorPolicies: []ActorPolicy{{Actor: "ci-*", ContextMode: ContextModeBlock}}}
	old.ApplyDefaults()
	// Removed policy.
	gone := &Config{}
	gone.ApplyDefaults()
	if w := WeakensProtection(old, gone); len(w) == 0 || !strings.Contains(w[0], "removed actor policy") {
		t.Errorf("removing an actor policy should weaken; got %v", w)
	}
	// Downgraded mode.
	down := &Config{ActorPolicies: []ActorPolicy{{Actor: "ci-*", ContextMode: ContextModeConfirm}}}
	down.ApplyDefaults()
	if w := WeakensProtection(old, down); len(w) == 0 {
		t.Errorf("downgrading an actor policy from block should weaken; got %v", w)
	}
}

// TestWeakensProtectionNilSafe: nil configs never panic.
func TestWeakensProtectionNilSafe(t *testing.T) {
	if WeakensProtection(nil, &Config{}) != nil || WeakensProtection(&Config{}, nil) != nil {
		t.Error("nil config comparison should return nil, not panic")
	}
}
