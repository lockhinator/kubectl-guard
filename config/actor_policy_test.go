package config

import "testing"

func TestEffectiveModesForActor(t *testing.T) {
	cfg := &Config{
		ContextMode:   ContextModeConfirm,
		NamespaceMode: ContextModeConfirm,
		ActorPolicies: []ActorPolicy{
			{Actor: "claude-code", ContextMode: ContextModeBlock},
			{Actor: "ci-*", NamespaceMode: NamespaceModeBlock},
			{Actor: "human-*", ContextMode: ContextModeConfirm}, // cannot weaken
		},
	}

	cases := []struct {
		actor   string
		wantCtx string
		wantNS  string
	}{
		{actor: "claude-code", wantCtx: ContextModeBlock, wantNS: NamespaceModeConfirm},
		{actor: "ci-deploy", wantCtx: ContextModeConfirm, wantNS: NamespaceModeBlock},
		{actor: "alice", wantCtx: ContextModeConfirm, wantNS: NamespaceModeConfirm}, // unmatched
	}
	for _, tc := range cases {
		gotCtx, gotNS := cfg.EffectiveModesForActor(tc.actor, "", "")
		if gotCtx != tc.wantCtx || gotNS != tc.wantNS {
			t.Errorf("EffectiveModesForActor(%q) = (%s,%s), want (%s,%s)", tc.actor, gotCtx, gotNS, tc.wantCtx, tc.wantNS)
		}
	}

	// A policy cannot weaken: global block stays block for a confirm-policy actor.
	blockGlobal := &Config{
		ContextMode:   ContextModeBlock,
		ActorPolicies: []ActorPolicy{{Actor: "human-*", ContextMode: ContextModeConfirm}},
	}
	if got, _ := blockGlobal.EffectiveModesForActor("human-bob", "", ""); got != ContextModeBlock {
		t.Errorf("global block + actor confirm = %s, want block (cannot weaken)", got)
	}
}

func TestSetAndRemoveActorPolicy(t *testing.T) {
	cfg := &Config{}
	if !cfg.SetActorPolicy("claude-code", ContextModeBlock, "") {
		t.Fatal("SetActorPolicy should succeed")
	}
	if len(cfg.ActorPolicies) != 1 || cfg.ActorPolicies[0].ContextMode != ContextModeBlock {
		t.Fatalf("policy not set: %+v", cfg.ActorPolicies)
	}
	// Replace (same actor) rather than append.
	if !cfg.SetActorPolicy("claude-code", ContextModeConfirm, NamespaceModeBlock) {
		t.Fatal("replace should succeed")
	}
	if len(cfg.ActorPolicies) != 1 {
		t.Fatalf("replace appended instead: %+v", cfg.ActorPolicies)
	}
	if cfg.ActorPolicies[0].NamespaceMode != NamespaceModeBlock {
		t.Errorf("replace did not update namespace mode: %+v", cfg.ActorPolicies[0])
	}
	// Invalid inputs rejected.
	if cfg.SetActorPolicy("", ContextModeBlock, "") {
		t.Error("empty actor must be rejected")
	}
	if cfg.SetActorPolicy("x", "nonsense", "") {
		t.Error("invalid mode must be rejected")
	}
	// Remove.
	if !cfg.RemoveActorPolicy("claude-code") {
		t.Error("remove should report true")
	}
	if cfg.RemoveActorPolicy("claude-code") {
		t.Error("second remove should report false")
	}
}
