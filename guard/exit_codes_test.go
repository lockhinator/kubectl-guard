package guard

import (
	"errors"
	"testing"
)

func TestExitCodeConstants(t *testing.T) {
	// kubectl owns 0/1; guard decisions must use higher codes so an agent can
	// tell a guard intervention apart from a kubectl failure.
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"ExitSuccess", ExitSuccess, 0},
		{"ExitKubectlError", ExitKubectlError, 1},
		{"ExitBlocked", ExitBlocked, 2},
		{"ExitDenied", ExitDenied, 3},
		{"ExitNeedsConfirm", ExitNeedsConfirm, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestStripGuardFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantArgs   []string
		wantJSON   bool
	}{
		{
			name:     "no flags unchanged",
			args:     []string{"get", "pods"},
			wantArgs: []string{"get", "pods"},
			wantJSON: false,
		},
		{
			name:     "leading --json stripped",
			args:     []string{"--json", "get", "pods"},
			wantArgs: []string{"get", "pods"},
			wantJSON: true,
		},
		{
			name:     "trailing --json stripped",
			args:     []string{"get", "secret", "--json"},
			wantArgs: []string{"get", "secret"},
			wantJSON: true,
		},
		{
			name:     "--json=true stripped",
			args:     []string{"--json=true", "get", "pods"},
			wantArgs: []string{"get", "pods"},
			wantJSON: true,
		},
		{
			name:     "--json=false stripped and disables",
			args:     []string{"--json=false", "get", "pods"},
			wantArgs: []string{"get", "pods"},
			wantJSON: false,
		},
		{
			name:     "--json mid-args stripped, others preserved",
			args:     []string{"--context", "prod", "--json", "delete", "pod", "nginx"},
			wantArgs: []string{"--context", "prod", "delete", "pod", "nginx"},
			wantJSON: true,
		},
		{
			name:     "--json after -- is positional, not stripped",
			args:     []string{"exec", "pod", "--", "--json"},
			wantArgs: []string{"exec", "pod", "--", "--json"},
			wantJSON: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, gotJSON := StripGuardFlags(tt.args)
			if gotJSON != tt.wantJSON {
				t.Errorf("jsonMode = %v, want %v", gotJSON, tt.wantJSON)
			}
			if !equalStringSlices(gotArgs, tt.wantArgs) {
				t.Errorf("filtered args = %v, want %v", gotArgs, tt.wantArgs)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestJSONForResult(t *testing.T) {
	t.Run("blocked surfaces protected resource", func(t *testing.T) {
		jr := JSONForResult(Blocked, "prod-cluster", "get secret", []string{"get", "secret"}, nil)
		if jr.Decision != "blocked" {
			t.Errorf("decision = %q, want blocked", jr.Decision)
		}
		if jr.Reason != "protected-resource" {
			t.Errorf("reason = %q, want protected-resource", jr.Reason)
		}
		if jr.Context != "prod-cluster" {
			t.Errorf("context = %q, want prod-cluster", jr.Context)
		}
		if jr.Command != "get secret" {
			t.Errorf("command = %q, want 'get secret'", jr.Command)
		}
		if jr.Resource != "secret" {
			t.Errorf("resource = %q, want secret", jr.Resource)
		}
	})

	t.Run("denied with error surfaces message", func(t *testing.T) {
		jr := JSONForResult(Deny, "", "get pods", []string{"get", "pods"}, errors.New("cannot load config: boom"))
		if jr.Decision != "denied" {
			t.Errorf("decision = %q, want denied", jr.Decision)
		}
		if jr.Reason != "cannot load config: boom" {
			t.Errorf("reason = %q, want the error text", jr.Reason)
		}
		if jr.Resource != "" {
			t.Errorf("resource = %q, want empty", jr.Resource)
		}
	})

	t.Run("denied without error is fail-closed", func(t *testing.T) {
		jr := JSONForResult(Deny, "", "get pods", []string{"get", "pods"}, nil)
		if jr.Reason != "fail-closed" {
			t.Errorf("reason = %q, want fail-closed", jr.Reason)
		}
	})

	t.Run("needs-confirmation is aborted", func(t *testing.T) {
		jr := JSONForResult(RequireConfirmation, "prod-cluster", "delete pod nginx", []string{"delete", "pod", "nginx"}, nil)
		if jr.Decision != "needs-confirmation" {
			t.Errorf("decision = %q, want needs-confirmation", jr.Decision)
		}
		if jr.Reason != "aborted" {
			t.Errorf("reason = %q, want aborted", jr.Reason)
		}
	})

	t.Run("allow yields empty decision", func(t *testing.T) {
		jr := JSONForResult(Allow, "dev", "get pods", []string{"get", "pods"}, nil)
		if jr.Decision != "" {
			t.Errorf("decision = %q, want empty for Allow", jr.Decision)
		}
	})
}
