package config

import (
	"reflect"
	"testing"
)

func TestInitFromEnv(t *testing.T) {
	t.Setenv(EnvProtectedContexts, "prod-*, prod-cluster")
	t.Setenv(EnvProtectedResources, "secret,configmap")
	t.Setenv(EnvConfirmMode, ConfirmModeTypeName)

	cfg, ok := InitFromEnv()
	if !ok {
		t.Fatal("ok = false, want true (protection values were provided)")
	}
	if !reflect.DeepEqual(cfg.ProtectedContexts, []string{"prod-*", "prod-cluster"}) {
		t.Errorf("ProtectedContexts = %v, want [prod-* prod-cluster]", cfg.ProtectedContexts)
	}
	if !reflect.DeepEqual(cfg.ProtectedResources, []string{"secret", "configmap"}) {
		t.Errorf("ProtectedResources = %v, want [secret configmap]", cfg.ProtectedResources)
	}
	if cfg.ConfirmMode != ConfirmModeTypeName {
		t.Errorf("ConfirmMode = %q, want %q", cfg.ConfirmMode, ConfirmModeTypeName)
	}
}

func TestInitFromEnvEmpty(t *testing.T) {
	t.Setenv(EnvProtectedContexts, "")
	t.Setenv(EnvProtectedResources, "")
	t.Setenv(EnvConfirmMode, "")

	_, ok := InitFromEnv()
	if ok {
		t.Error("ok = true, want false when no protection values are set")
	}
}

func TestInitFromEnvIgnoresInvalidConfirmMode(t *testing.T) {
	t.Setenv(EnvProtectedContexts, "prod-*")
	t.Setenv(EnvConfirmMode, "bogus")

	cfg, ok := InitFromEnv()
	if !ok {
		t.Fatal("ok = false, want true (contexts provided)")
	}
	// An invalid mode is ignored; ApplyDefaults restores the default.
	if cfg.ConfirmMode != ConfirmModeSimple {
		t.Errorf("ConfirmMode = %q, want default %q", cfg.ConfirmMode, ConfirmModeSimple)
	}
}

func TestInitFromFlags(t *testing.T) {
	cfg := InitFromFlags("prod-*,prod-cluster", "secret", ConfirmModeTypeName)
	if !reflect.DeepEqual(cfg.ProtectedContexts, []string{"prod-*", "prod-cluster"}) {
		t.Errorf("ProtectedContexts = %v", cfg.ProtectedContexts)
	}
	if !reflect.DeepEqual(cfg.ProtectedResources, []string{"secret"}) {
		t.Errorf("ProtectedResources = %v", cfg.ProtectedResources)
	}
	if cfg.ConfirmMode != ConfirmModeTypeName {
		t.Errorf("ConfirmMode = %q, want %q", cfg.ConfirmMode, ConfirmModeTypeName)
	}
}
