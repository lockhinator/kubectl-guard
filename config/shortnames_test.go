package config

import (
	"math/rand"
	"testing"
)

func TestNormalizeResourceBuiltins(t *testing.T) {
	tests := []struct{ in, want string }{
		{"cm", "configmap"},
		{"configmaps", "configmap"},
		{"configmap", "configmap"},
		{"secret", "secret"},
		{"secrets", "secret"},
		{"Secret", "secret"},
		{"pod", "pod"},
		{"pods", "pod"},
		{"po", "pod"},
		// Canonical forms ending in "s" must NOT be over-stripped, and their
		// short names / plurals must resolve to the same canonical form.
		{"ingress", "ingress"},
		{"ing", "ingress"},
		{"ingresses", "ingress"},
		{"storageclass", "storageclass"},
		{"sc", "storageclass"},
		{"storageclasses", "storageclass"},
		{"priorityclass", "priorityclass"},
		{"pc", "priorityclass"},
		// The one "-ies" plural built-in (networkpolicy -> networkpolicies).
		{"networkpolicy", "networkpolicy"},
		{"netpol", "networkpolicy"},
		{"networkpolicies", "networkpolicy"},
		// Group/name suffixes are stripped.
		{"secret.v1", "secret"},
		{"pods/foo", "pod"},
		// Unknown resources still singularize naively (unchanged fallback).
		{"widget", "widget"},
		{"widgets", "widget"},
		{"zz", "zz"},
	}
	for _, tt := range tests {
		if got := NormalizeResource(tt.in); got != tt.want {
			t.Errorf("NormalizeResource(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestBuiltinShortNamesEndingInS is the focused regression for the pre-existing
// bug where "ingress"/"storageclass"/"priorityclass" (canonical forms ending in
// "s") were over-stripped, so protecting them did NOT block their short names.
func TestBuiltinShortNamesEndingInS(t *testing.T) {
	cases := []struct{ protect, candidate string }{
		{"ingress", "ing"}, {"ingress", "ingresses"}, {"ingress", "Ingress"},
		{"storageclass", "sc"}, {"storageclass", "storageclasses"},
		{"priorityclass", "pc"}, {"priorityclass", "priorityclasses"},
		{"networkpolicy", "netpol"}, {"networkpolicy", "networkpolicies"},
		{"networkpolicies", "netpol"}, {"networkpolicies", "networkpolicy"},
	}
	for _, c := range cases {
		cfg := &Config{ProtectedResources: []string{c.protect}}
		if !cfg.IsResourceProtected(c.candidate) {
			t.Errorf("protect %q must block %q (built-in short name / plural)", c.protect, c.candidate)
		}
	}
}

// TestEveryBuiltinShortNameMatchesCanonical is the exhaustive guard against the
// over-strip class of bug: for EVERY built-in short name, protecting its
// canonical kind must block the short name, and protecting the short name must
// block the canonical kind. Any built-in whose plural rule the normalizer
// mishandles fails here rather than shipping as a silent gap.
func TestEveryBuiltinShortNameMatchesCanonical(t *testing.T) {
	for short, canonical := range resourceShortNames {
		// protect canonical -> block short name
		if !(&Config{ProtectedResources: []string{canonical}}).IsResourceProtected(short) {
			t.Errorf("protect %q must block its short name %q", canonical, short)
		}
		// protect short name -> block canonical
		if !(&Config{ProtectedResources: []string{short}}).IsResourceProtected(canonical) {
			t.Errorf("protect short name %q must block canonical %q", short, canonical)
		}
		// canonical and its short name normalize to the same token
		if NormalizeResource(short) != NormalizeResource(canonical) {
			t.Errorf("NormalizeResource(%q)=%q != NormalizeResource(%q)=%q",
				short, NormalizeResource(short), canonical, NormalizeResource(canonical))
		}
	}
}

// TestDiscoveredIrregularPluralCRD: a CRD whose plural is irregular
// (ciliumnetworkpolicy -> ciliumnetworkpolicies) is caught in EVERY typed form —
// kind, short name, and the typed plural — once discovery maps its short name and
// plural name to the canonical kind.
func TestDiscoveredIrregularPluralCRD(t *testing.T) {
	cfg := &Config{ProtectedResources: []string{"ciliumnetworkpolicy"}}
	cfg.SetDiscoveredShortNames(map[string]string{
		"cnp":                   "ciliumnetworkpolicy", // short name
		"ciliumnetworkpolicies": "ciliumnetworkpolicy", // irregular plural NAME
	})
	for _, form := range []string{"ciliumnetworkpolicy", "cnp", "ciliumnetworkpolicies"} {
		if !cfg.IsResourceProtected(form) {
			t.Errorf("protect ciliumnetworkpolicy must block %q", form)
		}
	}
}

func TestDiscoveredExpand(t *testing.T) {
	d := map[string]string{"ss": "secretstore", "es": "externalsecret"}
	if got := discoveredExpand("ss", d); got != "secretstore" {
		t.Errorf("discoveredExpand(ss) = %q", got)
	}
	if got := discoveredExpand("SS", d); got != "secretstore" {
		t.Errorf("discoveredExpand(SS) = %q (case-insensitive)", got)
	}
	if got := discoveredExpand("ss.external-secrets.io", d); got != "secretstore" {
		t.Errorf("discoveredExpand with group = %q", got)
	}
	if got := discoveredExpand("pod", d); got != "" {
		t.Errorf("discoveredExpand(pod) = %q, want empty (not a discovered short name)", got)
	}
	if got := discoveredExpand("ss", nil); got != "" {
		t.Errorf("discoveredExpand with nil map = %q, want empty", got)
	}
}

func TestIsResourceProtectedWithDiscovered(t *testing.T) {
	cfg := &Config{ProtectedResources: []string{"secretstore"}}
	// Without discovery, the short name does not resolve.
	if cfg.IsResourceProtected("ss") {
		t.Error("without discovery, 'ss' should not match 'secretstore'")
	}
	// With discovery, it does.
	cfg.SetDiscoveredShortNames(map[string]string{"ss": "secretstore"})
	if !cfg.IsResourceProtected("ss") {
		t.Error("with discovery, 'ss' must match protected 'secretstore'")
	}
	// The full/plural forms match with or without discovery.
	if !cfg.IsResourceProtected("secretstore") || !cfg.IsResourceProtected("secretstores") {
		t.Error("full and plural forms must always match")
	}
	// A user who protects BY the short name is also matched (both sides normalize
	// through the discovered map).
	cfg2 := &Config{ProtectedResources: []string{"ss"}}
	cfg2.SetDiscoveredShortNames(map[string]string{"ss": "secretstore"})
	if !cfg2.IsResourceProtected("secretstore") {
		t.Error("protecting by short name 'ss' must match the full 'secretstore'")
	}
}

// TestDiscoveryDoesNotUnprotect pins the confirmed bypasses: a discovered (or
// cache-poisoned) map keyed on a form of a protected resource must NOT remove
// protection. These exact witnesses were found by adversarial review.
func TestDiscoveryDoesNotUnprotect(t *testing.T) {
	cases := []struct {
		protect    string
		discovered map[string]string
		candidate  string
	}{
		// The severe one: the PLURAL of the flagship "secret" resource.
		{"secret", map[string]string{"secrets": "externalsecret"}, "secret"},
		{"secret", map[string]string{"secrets": "externalsecret"}, "secrets"},
		// A discovered key equal to a built-in canonical value.
		{"po", map[string]string{"pod": "widget"}, "pod"},
		{"po", map[string]string{"pod": "widget"}, "pods"},
		// A discovered key equal to a protected canonical token, plural candidate.
		{"service", map[string]string{"service": "externalsecret"}, "svcs"},
		{"service", map[string]string{"service": "externalsecret"}, "services"},
	}
	for _, c := range cases {
		cfg := &Config{ProtectedResources: []string{c.protect}}
		cfg.SetDiscoveredShortNames(c.discovered)
		if !cfg.IsResourceProtected(c.candidate) {
			t.Errorf("protect %q, discovered %v: get %q must stay BLOCKED (discovery must never un-protect)",
				c.protect, c.discovered, c.candidate)
		}
	}
}

// TestDiscoveryOnlyAddsFuzz is the security invariant enforced by differential
// testing: for any protected list, any discovered map, and any candidate, adding
// the discovered map can only make MORE things match, never fewer. A downgrade
// (protected without discovery, unprotected with it) is a fail-open.
//
// This test earned its place: an earlier implementation that layered the
// discovered map into the normalization of BOTH the candidate AND the protected
// entry produced ~7k downgrades per 2M iterations here.
func TestDiscoveryOnlyAddsFuzz(t *testing.T) {
	vocab := []string{
		"secret", "secrets", "sec", "po", "pod", "pods", "cm", "cms", "configmap",
		"configmaps", "ss", "secretstore", "secretstores", "es", "externalsecret",
		"ing", "ingress", "ingresses", "sc", "storageclass", "node", "nodes", "no",
		"svc", "service", "services", "widget", "widgets", "all", "*", "x", "zz",
	}
	r := rand.New(rand.NewSource(0xF29))
	pick := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = vocab[r.Intn(len(vocab))]
		}
		return out
	}

	const iters = 500000
	checked := 0
	for i := 0; i < iters; i++ {
		protect := pick(1 + r.Intn(3))
		discovered := map[string]string{}
		for j := 0; j < r.Intn(3); j++ {
			discovered[vocab[r.Intn(len(vocab))]] = vocab[r.Intn(len(vocab))]
		}
		candidate := vocab[r.Intn(len(vocab))]

		base := &Config{ProtectedResources: protect}
		withDisc := &Config{ProtectedResources: protect}
		withDisc.SetDiscoveredShortNames(discovered)

		if base.IsResourceProtected(candidate) {
			checked++
			if !withDisc.IsResourceProtected(candidate) {
				t.Fatalf("DOWNGRADE: protect=%v discovered=%v candidate=%q was protected, discovery un-protected it",
					protect, discovered, candidate)
			}
		}
	}
	if checked < 10000 {
		t.Fatalf("only %d base-protected cases exercised; generator too weak", checked)
	}
	t.Logf("no downgrades over %d base-protected cases", checked)
}

func TestShouldDiscoverShortNames(t *testing.T) {
	tru, fls := true, false
	if !(&Config{}).ShouldDiscoverShortNames() {
		t.Error("default (nil) must enable discovery")
	}
	if !(&Config{DiscoverShortNames: &tru}).ShouldDiscoverShortNames() {
		t.Error("explicit true must enable discovery")
	}
	if (&Config{DiscoverShortNames: &fls}).ShouldDiscoverShortNames() {
		t.Error("explicit false must disable discovery")
	}
}
